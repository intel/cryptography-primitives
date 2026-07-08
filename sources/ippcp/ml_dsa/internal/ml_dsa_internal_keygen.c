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
#include "hash/pcphashmethod_rmf.h"
#include "stateless_pqc/ml_dsa/ml_dsa.h"

/*
 * Algorithm 6. ML-DSA.KeyGen_internal(ksi)
 * Uses randomness to generate private and public keys.
 *      ksi       - input parameter with generated randomness
 *      pk        - output pointer to the output public key
 *      sk        - output pointer to the output private key
 *      mldsaCtx  - input pointer to ML DSA state
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_MLDSA_keyGen_internal, (const Ipp8u* ksi,
                                                   Ipp8u* pk,
                                                   Ipp8u* sk,
                                                   IppsMLDSAState* mldsaCtx))
/* clang-format on */
{
    IppStatus sts = ippStsErr;
    Ipp8u hash_output[128];
    Ipp8u k                   = mldsaCtx->params.k;
    Ipp8u l                   = mldsaCtx->params.l;
    _cpMLDSAStorage* pStorage = &mldsaCtx->storage;

    Ipp8u* rho  = hash_output; // 32 bytes
    Ipp8u* rho_ = rho + 32;    // 64 bytes
    Ipp8u* K    = rho_ + 64;   // 32 bytes

    IppPoly* s1 = NULL;
    IppPoly* s2 = NULL;
    IppPoly* t  = NULL;
    IppPoly* t0 = NULL;
    IppPoly* t1 = NULL;

    // Initialize the temporary storage
    {
        IppsHashMethod hash_method_struct;
        sts = ippsHashMethodSet_SHAKE256(&hash_method_struct, 128 * 8);
        if (sts != ippStsNoErr)
            goto exit;

        Ipp8u hash_input[34];
        CopyBlock(ksi, hash_input, 32);
        hash_input[32] = k;
        hash_input[33] = l;

        sts = ippsHashMessage_rmf(hash_input, 34, hash_output, &hash_method_struct);
        PurgeBlock(hash_input, sizeof(hash_input)); // zeroize ksi copy
        if (sts != ippStsNoErr)
            goto exit;
    }

    s1 = (IppPoly*)cp_mlStorageAllocate(pStorage, l * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    s2 = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    t  = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    if (s1 == NULL || s2 == NULL || t == NULL) {
        sts = ippStsMemAllocErr;
        goto exit;
    }

    sts = cp_ml_expandS(rho_, s1, s2, mldsaCtx);
    if (sts != ippStsNoErr)
        goto exit;

    // 𝐭 = NTT^−1(𝐀 * NTT(𝐬1)) + 𝐬2
    {
        IppPoly* NTT_s1 =
            (IppPoly*)cp_mlStorageAllocate(pStorage, l * sizeof(IppPoly) + CP_ML_ALIGNMENT);
        if (NTT_s1 == NULL) {
            sts = ippStsMemAllocErr;
            goto exit;
        }

        for (Ipp8u i = 0; i < l; i++) {
            cp_ml_NTT_output(s1 + i, NTT_s1 + i);
        }

        sts = cp_ml_expandMatrixMultiplyVectorNTT(rho, NTT_s1, t, mldsaCtx);
        if (sts != ippStsNoErr)
            goto exit;
        sts = cp_mlStorageRelease(pStorage, l * sizeof(IppPoly) + CP_ML_ALIGNMENT); // NTT_s1
        if (sts != ippStsNoErr)
            goto exit;
    }

    for (Ipp8u i = 0; i < k; i++) {
        cp_ml_inverseNTT(t + i, 1);
        cp_ml_addNTT(t + i, s2 + i, t + i);
    }

    t0 = t;
    t1 = (IppPoly*)cp_mlStorageAllocate(pStorage, k * sizeof(IppPoly) + CP_ML_ALIGNMENT);
    if (t1 == NULL) {
        sts = ippStsMemAllocErr;
        goto exit;
    }

    // Compress t
    cp_ml_power2RoundVector(t, t0, t1, k);

    cp_ml_pkEncode(rho, t1, pk, mldsaCtx);
    // Encode secret key
    {
        Ipp8u tr[64];
        IppsHashMethod hash_method_struct;
        sts = ippsHashMethodSet_SHAKE256(&hash_method_struct, 64 * 8);
        if (sts != ippStsNoErr)
            goto exit;
        sts = ippsHashMessage_rmf(pk, 32 + 32 * k * CP_ML_DSA_BITLEN_Q_D, tr, &hash_method_struct);
        if (sts != ippStsNoErr) {
            PurgeBlock(tr, sizeof(tr)); // zeroize secrets
            goto exit;
        }

        cp_ml_skEncode(rho, K, tr, s1, s2, t0, sk, mldsaCtx);
        PurgeBlock(tr, sizeof(tr)); // zeroize secrets
    }
    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage,
                              (3 * k + l) * sizeof(IppPoly) + 4 * CP_ML_ALIGNMENT); // s1,s2,t,t1
    if (sts != ippStsNoErr)
        goto exit;

exit:
    /* Zeroize sensitive stack buffer on every exit path */
    PurgeBlock(hash_output, sizeof(hash_output)); // rho, rho_, K
    return sts;
}
