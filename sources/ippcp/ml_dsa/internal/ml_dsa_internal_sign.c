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
 * Algorithm 7. ML-DSA.Sign_internal(sk, M, rnd)
 * Sign the message M with the ctx context using the sk private key and rnd randomness.
 *      M         - input parameter with the message to be signed
 *      msg_size  - input parameter with the message size
 *      ctx       - input parameter with the context
 *      ctx_size  - input parameter with the context size
 *      sk        - input parameter with the private key
 *      rnd       - input parameter with generated randomness
 *      sig       - output pointer to the output signature
 *      mldsaCtx  - input pointer to ML DSA state
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus,  cp_MLDSA_Sign_internal, (const Ipp8u* M,
                                                  Ipp32s msg_size,
                                                  const Ipp8u* ctx,
                                                  Ipp32s ctx_size,
                                                  const Ipp8u* sk,
                                                  Ipp8u* rnd,
                                                  Ipp8u* sig,
                                                  IppsMLDSAState* mldsaCtx))
/* clang-format on */
{
    IppStatus sts = ippStsErr;
    Ipp8u decode_output[128];
    Ipp8u k        = mldsaCtx->params.k;
    Ipp8u l        = mldsaCtx->params.l;
    Ipp8u lambda_4 = mldsaCtx->params.lambda_div_4;

    Ipp8u* rho                = decode_output; // 32 bytes
    Ipp8u* K                  = rho + 32;      // 32 bytes
    Ipp8u* tr                 = K + 32;        // 64 bytes
    _cpMLDSAStorage* pStorage = &mldsaCtx->storage;
    IppsHashMethod shake256_method;

#if !CP_ML_MEMORY_OPTIMIZATION
    IppPoly* A =
        (IppPoly*)cp_mlStorageAllocate(pStorage, k * l * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((A == NULL), ippStsMemAllocErr);

#endif // !CP_ML_MEMORY_OPTIMIZATION
    IppPoly* s1 = (IppPoly*)cp_mlStorageAllocate(pStorage, l * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IppPoly* s2 = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IppPoly* t0 = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((s1 == NULL || s2 == NULL || t0 == NULL), ippStsMemAllocErr);

    cp_ml_skDecode(sk, rho, K, tr, s1, s2, t0, mldsaCtx);

    for (Ipp8u i = 0; i < l; i++) {
        cp_ml_NTT(s1 + i);
    }

    for (Ipp8u i = 0; i < k; i++) {
        cp_ml_NTT(s2 + i);
        cp_ml_NTT(t0 + i);
    }
    // mu = H(BytesToBits(tr)||M_, 64)
    Ipp8u mu[64];
    {
        Ipp32s input_size = 64 + 2 + ctx_size + msg_size;
        Ipp8u* hash_input = cp_mlStorageAllocate(pStorage, input_size + CP_ML_ALIGNMENT);
        IPP_BADARG_RET((hash_input == NULL), ippStsMemAllocErr);

        CopyBlock(tr, hash_input, 64);
        PurgeBlock(tr, 64); // zeroize secrets
        // M_ = BytesToBits(IntegerToBytes(0,1) || IntegerToBytes(|ctx|, 1) || ctx) || 𝑀
        hash_input[64] = 0;
        hash_input[65] = (Ipp8u)ctx_size & 0xFF;
        CopyBlock(ctx, hash_input + 66, ctx_size);
        CopyBlock(M, hash_input + 66 + ctx_size, msg_size);

        sts = ippsHashMethodSet_SHAKE256(&shake256_method, (64 * 8));
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        sts = ippsHashMessage_rmf(hash_input, input_size, mu, &shake256_method);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        sts = cp_mlStorageRelease(pStorage, input_size + CP_ML_ALIGNMENT); // hash_input
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
    // rho__ = H(K||rnd||mu,64)
    Ipp8u rho__[64];
    {
        Ipp8u temp[32 + 32 + 64];
        CopyBlock(K, temp, 32);
        PurgeBlock(K, 32); // zeroize secrets
        CopyBlock(rnd, temp + 32, 32);
        CopyBlock(mu, temp + 64, 64);
        sts = ippsHashMethodSet_SHAKE256(&shake256_method, (64 * 8));
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        sts = ippsHashMessage_rmf(temp, 32 + 32 + 64, rho__, &shake256_method);
        PurgeBlock(temp, sizeof(temp)); // zeroize secrets
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
#if !CP_ML_MEMORY_OPTIMIZATION
    sts = cp_ml_expandA(rho, A, mldsaCtx);
    PurgeBlock(rho, 32); // zeroize secrets
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
#endif                   // !CP_ML_MEMORY_OPTIMIZATION
    IppPoly* z = (IppPoly*)cp_mlStorageAllocate(pStorage, l * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IppPoly* w = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IppPoly* h = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((z == NULL || w == NULL || h == NULL), ippStsMemAllocErr);

    Ipp32u kappa = 0;
    int iter     = 0;

    while (iter < CP_ML_DSA_MAX_SIGN_ITERATIONS) {
        iter++;
        Ipp32s check_1 = 0, check_2 = 0;
        IppPoly* y = z;
        sts        = cp_ml_expandMask(rho__, kappa, y, mldsaCtx);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);

        // 𝐰 = NTT^−1(𝐀 * NTT(𝐲))
        {
            IppPoly* NTT_y =
                (IppPoly*)cp_mlStorageAllocate(pStorage, l * sizeof(IppPoly) + CP_ML_ALIGNMENT);
            IPP_BADARG_RET((NTT_y == NULL), ippStsMemAllocErr);

            for (Ipp8u i = 0; i < l; i++) {
                cp_ml_NTT_output(y + i, NTT_y + i);
            }
#if CP_ML_MEMORY_OPTIMIZATION
            sts = cp_ml_expandMatrixMultiplyVectorNTT(rho, NTT_y, w, mldsaCtx);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
#else
            cp_ml_matrixVectorNTT(A, NTT_y, w, l, k);
#endif // CP_ML_MEMORY_OPTIMIZATION

            sts = cp_mlStorageRelease(pStorage, l * sizeof(IppPoly) + CP_ML_ALIGNMENT); // NTT_y
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }
        for (Ipp8u i = 0; i < k; i++) {
            cp_ml_inverseNTT(w + i, 1);
        }

        Ipp8u* c_ = sig; // first lambda/4 bytes
        {
            IppPoly* w1 =
                (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
            IPP_BADARG_RET((w1 == NULL), ippStsMemAllocErr);

            cp_ml_highBitsVector(w, mldsaCtx->params.gamma_2, w1, k);

            // commitment hash
            // 𝑐 = H(mu||w1Encode(𝐰1), 𝜆/4)
            {
                Ipp32s encodeSize =
                    32 * k *
                    cp_ml_bitlen((Ipp32u)((CP_ML_DSA_Q - 1) / (2 * mldsaCtx->params.gamma_2) - 1));
                Ipp8u* hash_input =
                    cp_mlStorageAllocate(pStorage, (64 + encodeSize) + CP_ML_ALIGNMENT);
                IPP_BADARG_RET((hash_input == NULL), ippStsMemAllocErr);

                CopyBlock(mu, hash_input, 64);
                cp_ml_w1Encode(w1, hash_input + 64, mldsaCtx);

                sts = ippsHashMethodSet_SHAKE256(&shake256_method, (lambda_4 * 8));
                IPP_BADARG_RET((sts != ippStsNoErr), sts);
                sts = ippsHashMessage_rmf(hash_input, 64 + encodeSize, c_, &shake256_method);
                IPP_BADARG_RET((sts != ippStsNoErr), sts);
                sts = cp_mlStorageRelease(pStorage,
                                          (64 + encodeSize) + CP_ML_ALIGNMENT); // hash_input
                IPP_BADARG_RET((sts != ippStsNoErr), sts);
            }
            sts = cp_mlStorageRelease(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT); // w1
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }

        IppPoly* c = h;
        sts        = cp_ml_sampleInBall(c_, c, mldsaCtx);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        cp_ml_NTT(c);

        // z = y + NTT^−1(𝑐 * s1)
        {
            IppPoly* NTT_c_s1 =
                (IppPoly*)cp_mlStorageAllocate(pStorage, l * sizeof(IppPoly) + CP_ML_ALIGNMENT);
            IPP_BADARG_RET((NTT_c_s1 == NULL), ippStsMemAllocErr);

            for (Ipp8u i = 0; i < l; i++) {
                cp_ml_multiplyNTT(c, s1 + i, NTT_c_s1 + i);
                cp_ml_inverseNTT(NTT_c_s1 + i, 1);
                cp_ml_addNTT(y + i, NTT_c_s1 + i, z + i);
            }
            sts = cp_mlStorageRelease(pStorage, l * sizeof(IppPoly) + CP_ML_ALIGNMENT); // NTT_c_s1
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }
        check_1 = cp_ml_polyInfinityNormCheck(z, l);

        IppPoly* NTT_c_s2 =
            (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
        IPP_BADARG_RET((NTT_c_s2 == NULL), ippStsMemAllocErr);

        for (Ipp8u i = 0; i < k; i++) {
            cp_ml_multiplyNTT(c, s2 + i, NTT_c_s2 + i);
            cp_ml_inverseNTT(NTT_c_s2 + i, 0);
        }
        {
            IppPoly* r0 =
                (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
            IPP_BADARG_RET((r0 == NULL), ippStsMemAllocErr);

            for (Ipp8u i = 0; i < k; i++) {
                cp_ml_subNTT(w + i, NTT_c_s2 + i, r0 + i);
                cp_ml_lowBits(r0 + i, mldsaCtx->params.gamma_2, r0 + i);
            }
            check_2 = cp_ml_polyInfinityNormCheck(r0, k);
            sts     = cp_mlStorageRelease(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT); // r0
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }
        if (!(check_1 >= mldsaCtx->params.gamma_1 - mldsaCtx->params.beta ||
              check_2 >= mldsaCtx->params.gamma_2 - mldsaCtx->params.beta)) {
            Ipp32s check_3 = 0, check_4 = 0;
            {
                IppPoly* NTT_c_t0 =
                    (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
                IPP_BADARG_RET((NTT_c_t0 == NULL), ippStsMemAllocErr);

                for (Ipp8u i = 0; i < k; i++) {
                    cp_ml_multiplyNTT(c, t0 + i, NTT_c_t0 + i);
                    cp_ml_inverseNTT(NTT_c_t0 + i, 1);
                }
                // h = MakeHint(−NTT_c_t0, w - NTT_c_s2 + NTT_c_t0)
                for (Ipp8u i = 0; i < k; i++) {
                    for (Ipp32u j = 0; j < CP_ML_N; j++) {
                        h[i].values[j] = cp_ml_makeHint(-NTT_c_t0[i].values[j],
                                                        w[i].values[j] - NTT_c_s2[i].values[j] +
                                                            NTT_c_t0[i].values[j],
                                                        mldsaCtx->params.gamma_2);
                    }
                }
                check_3 = cp_ml_polyInfinityNormCheck(NTT_c_t0, k);
                sts     = cp_mlStorageRelease(pStorage,
                                          k * sizeof(IppPoly) + CP_ML_ALIGNMENT); // NTT_c_t0
                IPP_BADARG_RET((sts != ippStsNoErr), sts);
            }
            check_4 = cp_ml_countOnes(h, k);
            if (!(check_3 >= mldsaCtx->params.gamma_2 || check_4 > mldsaCtx->params.omega)) {
                sts = cp_mlStorageRelease(pStorage,
                                          k * sizeof(IppPoly) + CP_ML_ALIGNMENT); // NTT_c_s2
                IPP_BADARG_RET((sts != ippStsNoErr), sts);
                break;                                                            // accept
            }
        }
        kappa += l;
        sts = cp_mlStorageRelease(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT); // NTT_c_s2
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
    PurgeBlock(rho__, sizeof(rho__)); // zeroize secrets
    PurgeBlock(mu, sizeof(mu));       // zeroize secrets
#if CP_ML_MEMORY_OPTIMIZATION
    PurgeBlock(rho, 32);              // zeroize secrets
#endif                                // CP_ML_MEMORY_OPTIMIZATION

    if (iter >= CP_ML_DSA_MAX_SIGN_ITERATIONS) {
        // Release locally used storage
        sts = cp_mlStorageRelease(pStorage,
                                  (4 * k + 2 * l) * sizeof(IppPoly) +
                                      6 * CP_ML_ALIGNMENT); // z,h,w,s1,s2,t0
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
#if !CP_ML_MEMORY_OPTIMIZATION
        sts = cp_mlStorageRelease(pStorage, (k * l) * sizeof(IppPoly) + CP_ML_ALIGNMENT); // A
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
#endif                             // !CP_ML_MEMORY_OPTIMIZATION
        PurgeBlock(sig, lambda_4); // zeroize signature
        return ippStsMLDSAMaxIterations;
    }

    // z mod+- q
    cp_ml_sigEncode(z, h, sig, mldsaCtx);

    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage,
                              (4 * k + 2 * l) * sizeof(IppPoly) +
                                  6 * CP_ML_ALIGNMENT); // z,h,w,s1,s2,t0
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
#if !CP_ML_MEMORY_OPTIMIZATION
    sts = cp_mlStorageRelease(pStorage, (k * l) * sizeof(IppPoly) + CP_ML_ALIGNMENT); // A
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
#endif // !CP_ML_MEMORY_OPTIMIZATION
    return sts;
}
