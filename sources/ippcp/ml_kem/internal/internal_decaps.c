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
#include "ml_kem_internal/ml_kem.h"

/*
 * Uses the decapsulation key to produce a shared secret key from a ciphertext.
 *
 *      K          - output pointer to the generated shared secret key K of size 32 bytes
 *      ciphertext - input pointer to the ciphertext of size 32*(d_{u}*k + d_{v})) bytes
 *      inpDecKey  - input pointer to the decapsulation key (private key) of size 768*k + 96 bytes
 *      mlkemCtx   - input pointer to ML KEM context
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_MLKEMdecaps_internal, (Ipp8u K[CP_SHARED_SECRET_BYTES],
                                                  const Ipp8u* ciphertext,
                                                  const Ipp8u* inpDecKey,
                                                  IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    const Ipp8u k             = mlkemCtx->params.k;
    _cpMLKEMStorage* pStorage = &mlkemCtx->storage;

    int ciphertext_size = 0;
    switch (k) {
    case 2:  //IPPCP_ML_KEM_512
        ciphertext_size = 768;
        break;
    case 3:  // IPPCP_ML_KEM_768
        ciphertext_size = 1088;
        break;
    case 4:  // IPPCP_ML_KEM_1024
        ciphertext_size = 1568;
        break;
    default: // Invalid k value
        return ippStsBadArgErr;
    }

    IppStatus sts = ippStsNoErr;

    /* 1: dkPKE <- dk[0 : 384*k] */
    const Ipp8u* pPKE_DecKey = inpDecKey;
    /* 2: ekPKE <- dk[384*k : 768*k+32] */
    const Ipp8u* pPKE_EncKey = inpDecKey + 384 * k;
    /* 3: h <- dk[768*k+32 : 768*k+64] */
    const Ipp8u* h = inpDecKey + 768 * k + 32;
    /* 4: z <- dk[768*k+64 : 768*k+96] */
    const Ipp8u* z = inpDecKey + 768 * k + 64;

    /* 5: m` <- K-PKE.Decrypt(dkPKE, c) */
    Ipp8u message[32];
    sts = cp_KPKE_Decrypt(message, pPKE_DecKey, ciphertext, mlkemCtx);
    CP_CHECK_FREE_RET(sts != ippStsNoErr, sts, pStorage);

    /* 6: (K`, r`) <- G(m`||h) */

    // stores 32 bytes of K1, 32 bytes of r and 1 byte of N
    Ipp8u K1_r_N[CP_SHARED_SECRET_BYTES + 32 + 1];
    Ipp8u* K1  = K1_r_N;
    Ipp8u* r_N = K1_r_N + 32;

    /* m`||h */
    CopyBlock(message, K1_r_N, 32);
    CopyBlock(h, K1_r_N + 32, 32);
    /* G(m`||h) */
    sts = ippsHashMessage_rmf(K1_r_N, 64, K1_r_N, ippsHashMethod_SHA3_512());
    CP_CHECK_FREE_RET(sts != ippStsNoErr, sts, pStorage);

    /* 7: K`` <- J(z||c) */
    Ipp8u K2[CP_SHARED_SECRET_BYTES];
    const IppsHashMethod* hash_method = ippsHashMethod_SHAKE256(CP_SHARED_SECRET_BYTES * 8);
    int hash_size                     = 0;
    sts                               = ippsHashGetSizeOptimal_rmf(&hash_size, hash_method);
    CP_CHECK_FREE_RET(sts != ippStsNoErr, sts, pStorage);

    IppsHashState_rmf* hash_state =
        (IppsHashState_rmf*)cp_mlkemStorageAllocate(pStorage, hash_size + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(hash_state == NULL, ippStsMemAllocErr, pStorage);
    hash_state = IPP_ALIGNED_PTR(hash_state, CP_ML_KEM_ALIGNMENT);

    sts = ippsHashInit_rmf(hash_state, hash_method);
    CP_CHECK_FREE_RET(sts != ippStsNoErr, sts, pStorage);
    sts = ippsHashUpdate_rmf(z, 32, hash_state);
    CP_CHECK_FREE_RET(sts != ippStsNoErr, sts, pStorage);
    sts = ippsHashUpdate_rmf(ciphertext, ciphertext_size, hash_state);
    CP_CHECK_FREE_RET(sts != ippStsNoErr, sts, pStorage);
    sts = ippsHashFinal_rmf(K2, hash_state);
    CP_CHECK_FREE_RET(sts != ippStsNoErr, sts, pStorage);

    /* 8: c` <- K-PKE.Encrypt(ekPKE, m`, r`) */
    Ipp8u* ciphertext1 = cp_mlkemStorageAllocate(pStorage, ciphertext_size + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(ciphertext1 == NULL, ippStsMemAllocErr, pStorage);
    ciphertext1 = IPP_ALIGNED_PTR(ciphertext1, CP_ML_KEM_ALIGNMENT);
    sts         = cp_KPKE_Encrypt(ciphertext1, pPKE_EncKey, message, r_N, mlkemCtx);
    CP_CHECK_FREE_RET(sts != ippStsNoErr, sts, pStorage);

    /* 9-10: if c != c` then K` <- K`` */
    BNU_CHUNK_T is_equal = cpIsEquBlock_ct(ciphertext, ciphertext1, ciphertext_size);
    if (is_equal) {
        CopyBlock(K1, K, CP_SHARED_SECRET_BYTES);
    } else {
        CopyBlock(K2, K, CP_SHARED_SECRET_BYTES);
    }

    /* Release locally used storage */
    sts = cp_mlkemStorageRelease(pStorage, hash_size + CP_ML_KEM_ALIGNMENT); // hash_state
    sts |= cp_mlkemStorageRelease(pStorage,
                                  ciphertext_size + CP_ML_KEM_ALIGNMENT);    // ciphertext1

    return sts;
}
