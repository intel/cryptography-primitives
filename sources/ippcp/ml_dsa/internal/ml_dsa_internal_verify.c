/*************************************************************************
* Copyright (C) 2025 Intel Corporation
*
* Licensed under the Apache License,  Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* 	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law  or agreed  to  in  writing,  software
* distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the  specific  language  governing  permissions  and
* limitations under the License.
*************************************************************************/

//-------------------------------//
//      Level 1 functions
//-------------------------------//

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"

#include "stateless_pqc/ml_dsa/ml_dsa.h"

/*
 * cp_MLDSA_ComputeMu - Mu computation part
 * Compute the message hash Mu from the message M, ctx context, and pk public key.
 *      M         - input parameter with the message to be verified
 *      msg_size  - input parameter with the message size
 *      ctx       - input parameter with the context
 *      ctx_size  - input parameter with the context size
 *      pk        - input parameter with the public key
 *      mu        - output pointer to the computed Mu hash (64 bytes)
 *      mldsaCtx  - input pointer to ML DSA state
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus,  cp_MLDSA_ComputeMu, (const Ipp8u* M,
                                              Ipp32s msg_size,
                                              const Ipp8u* ctx,
                                              Ipp32s ctx_size,
                                              const Ipp8u* pk,
                                              Ipp8u* mu,
                                              IppsMLDSAState* mldsaCtx))
/* clang-format on */
{
    IppStatus sts             = ippStsErr;
    Ipp8u k                   = mldsaCtx->params.k;
    _cpMLDSAStorage* pStorage = &mldsaCtx->storage;
    IppsHashMethod shake256_method;

    Ipp8u tr[64];
    sts = ippsHashMethodSet_SHAKE256(&shake256_method, (64 * 8));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    sts = ippsHashMessage_rmf(pk, 32 + 32 * k * CP_ML_DSA_BITLEN_Q_D, tr, &shake256_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    Ipp32s input_size = 64 + 2 + ctx_size + msg_size;
    Ipp8u* hash_input = cp_mlStorageAllocate(pStorage, input_size + CP_ML_ALIGNMENT);
    if (hash_input == NULL) {
        PurgeBlock(tr, sizeof(tr));
        return ippStsMemAllocErr;
    }

    CopyBlock(tr, hash_input, 64);
    PurgeBlock(tr, sizeof(tr)); /* zeroize hashes */
    /* M_ = BytesToBits(IntegerToBytes(0,1) || IntegerToBytes(|ctx|, 1) || ctx) || 𝑀 */
    hash_input[64] = 0;
    hash_input[65] = (Ipp8u)ctx_size & 0xFF;
    if (ctx_size > 0) {
        CopyBlock(ctx, hash_input + 66, ctx_size);
    }
    CopyBlock(M, hash_input + 66 + ctx_size, msg_size);

    sts = ippsHashMessage_rmf(hash_input, input_size, mu, &shake256_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    sts = cp_mlStorageRelease(pStorage, input_size + CP_ML_ALIGNMENT); /* hash_input */
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    return sts;
}

/*
 * Algorithm 8. ML-DSA.Verify_internal(pk, M, sig) - Core verification part
 * Verify the sig signature using the pk public key and the pre-computed mu hash.
 *      mu        - input parameter with the pre-computed Mu hash (64 bytes)
 *      pk        - input parameter with the public key
 *      sig       - input parameter with the signature
 *      is_valid  - output pointer to the verification result. 1 - valid, 0 - invalid
 *      mldsaCtx  - input pointer to ML DSA state
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus,  cp_MLDSA_VerifyCore, (const Ipp8u* mu,
                                               const Ipp8u* pk,
                                               const Ipp8u* sig,
                                               Ipp32s* is_valid,
                                               IppsMLDSAState* mldsaCtx))
/* clang-format on */
{
    IppStatus sts             = ippStsErr;
    *is_valid                 = 0;
    Ipp8u k                   = mldsaCtx->params.k;
    Ipp8u l                   = mldsaCtx->params.l;
    Ipp8u lambda_4            = mldsaCtx->params.lambda_div_4;
    _cpMLDSAStorage* pStorage = &mldsaCtx->storage;

    IppPoly* z  = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IppPoly* h  = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IppPoly* w_ = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((z == NULL || h == NULL || w_ == NULL), ippStsMemAllocErr);

    sts = cp_ml_sigDecode(sig, z, h, mldsaCtx);
    IPP_BADARG_RET((sts != ippStsNoErr), ippStsNoErr);

    if (cp_ml_polyInfinityNormCheck(z, l) >= mldsaCtx->params.gamma_1 - mldsaCtx->params.beta) {
        return ippStsNoErr;
    }

    const Ipp8u* c_ = sig; // first lambda/4 bytes
    IppPoly c;
    sts = cp_ml_sampleInBall(c_, &c, mldsaCtx);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    // 𝐰_ = NTT^(−1)(𝐀 * NTT(𝐳) − NTT(𝑐) * NTT(𝐭1 * 2^d)) // 𝐰_ = 𝐀*𝐳 − 𝑐*𝐭1 * 2^d
    const Ipp8u* rho = pk; // first 32 bytes
    {
        for (Ipp8u i = 0; i < l; i++) {
            cp_ml_NTT(z + i);
        }
        cp_ml_expandMatrixMultiplyVectorNTT(rho, z, w_, mldsaCtx);
    }
    cp_ml_NTT(&c);

    IppPoly* t1 = z;
    cp_ml_pkDecode(pk, t1, mldsaCtx);
    for (Ipp8u i = 0; i < k; i++) {
        IppPoly* c_t1 = t1 + i;
        cp_ml_scalarNTT(t1 + i, c_t1, 1 << CP_ML_DSA_D);
        cp_ml_NTT(c_t1);
        cp_ml_multiplyNTT(&c, c_t1, c_t1);
        cp_ml_subNTT(w_ + i, c_t1, w_ + i);
        cp_ml_inverseNTT(w_ + i, 1);
    }

    // 𝐰1_ = UseHint(𝐡, 𝐰_)
    IppPoly* w1_ = h;
    cp_ml_useHintVector(h, w_, w1_, mldsaCtx->params.gamma_2, k);

    Ipp8u* c__ = cp_mlStorageAllocate(pStorage, lambda_4 + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((c__ == NULL), ippStsMemAllocErr);
    {
        IppsHashMethod shake256_method;
        Ipp32s encodeSize =
            32 * k * cp_ml_bitlen((Ipp32u)((CP_ML_DSA_Q - 1) / (2 * mldsaCtx->params.gamma_2) - 1));
        Ipp8u* hash_input = cp_mlStorageAllocate(pStorage, (64 + encodeSize) + CP_ML_ALIGNMENT);
        IPP_BADARG_RET((hash_input == NULL), ippStsMemAllocErr);

        CopyBlock(mu, hash_input, 64);
        cp_ml_w1Encode(w1_, hash_input + 64, mldsaCtx);

        sts = ippsHashMethodSet_SHAKE256(&shake256_method, (lambda_4 * 8));
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        sts = ippsHashMessage_rmf(hash_input, 64 + encodeSize, c__, &shake256_method);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        sts = cp_mlStorageRelease(pStorage, (64 + encodeSize) + CP_ML_ALIGNMENT); // hash_input
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
    // verify
    *is_valid = cpIsEquBlock_ct(c_, c__, lambda_4) & 1;

    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage, lambda_4 + CP_ML_ALIGNMENT);                    // c__
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    sts = cp_mlStorageRelease(pStorage, 3 * k * sizeof(IppPoly) + 3 * CP_ML_ALIGNMENT); // z,h,w_
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    return sts;
}

/*
 * cp_MLDSA_Verify_internal
 * Verify the message M with the ctx context using the pk public key and sig signature.
 *      M         - input parameter with the message to be verified
 *      msg_size  - input parameter with the message size
 *      ctx       - input parameter with the context
 *      ctx_size  - input parameter with the context size
 *      pk        - input parameter with the public key
 *      sig       - input parameter with the signature
 *      is_valid  - output pointer to the verification result. 1 - valid, 0 - invalid
 *      mldsaCtx  - input pointer to ML DSA state
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus,  cp_MLDSA_Verify_internal, (const Ipp8u* M,
                                                    Ipp32s msg_size,
                                                    const Ipp8u* ctx,
                                                    Ipp32s ctx_size,
                                                    const Ipp8u* pk,
                                                    const Ipp8u* sig,
                                                    Ipp32s* is_valid,
                                                    IppsMLDSAState* mldsaCtx))
/* clang-format on */
{
    IppStatus sts = ippStsErr;
    *is_valid     = 0;

    Ipp8u mu[64];
    sts = cp_MLDSA_ComputeMu(M, msg_size, ctx, ctx_size, pk, mu, mldsaCtx);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    sts = cp_MLDSA_VerifyCore(mu, pk, sig, is_valid, mldsaCtx);

    PurgeBlock(mu, sizeof(mu)); /* zeroize hashes */

    return sts;
}
