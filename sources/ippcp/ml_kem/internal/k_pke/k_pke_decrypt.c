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
/*
 * Level 2(K-PKE) function cp_KPKE_Decrypt
 */

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"
#include "ml_kem_internal/ml_kem.h"
#include "hash/pcphash_rmf.h"

/*
 * Uses the decryption key to decrypt a ciphertext.
 *
 *      message     - output pointer to the generated message of size 32 bytes
 *      pPKE_DecKey - input pointer to the decryption key of size 384*k bytes
 *      ciphertext  - input pointer to the ciphertext of size 32*(d_{u}*k+d_{v})) bytes
 *      mlkemCtx    - input pointer to the ML KEM context
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_KPKE_Decrypt, (Ipp8u * message,
                                          const Ipp8u* pPKE_DecKey,
                                          const Ipp8u* ciphertext,
                                          IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    IppStatus sts             = ippStsNoErr;
    const Ipp8u k             = mlkemCtx->params.k;
    const Ipp16u d_u          = mlkemCtx->params.d_u;
    const Ipp8u d_v           = mlkemCtx->params.d_v;
    _cpMLKEMStorage* pStorage = &mlkemCtx->storage;

    /* 1: c1 <- c[0 : 32*d_{u}*k] */
    Ipp8u* c1 = (Ipp8u*)ciphertext;
    /* 2: c2 <- c[32*d_{u}*k : 32(d_{u}*k + d_{v})] */
    Ipp8u* c2 = c1 + (32 * d_u * k);

    /* 3: u` <- Decompress_{d_{u}}(cp_byteDecode_{d_{u}}(c1)) */
    Ipp16sPoly* u =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage,
                                             k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(u == NULL, ippStsMemAllocErr, pStorage);
    u = IPP_ALIGNED_PTR(u, CP_ML_KEM_ALIGNMENT);
    for (Ipp8u i = 0; i < k; i++) {
        cp_byteDecode(&u[i], d_u, c1 + i * 32 * d_u);

        for (Ipp32u j = 0; j < 256; j++) {
            sts = cp_Decompress((Ipp16u*)&u[i].values[j], u[i].values[j], d_u);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }
    }

    /* 4: v` <- Decompress_{d_{v}}(cp_byteDecode_{d_{v}}(c2)) */
    Ipp16sPoly* v =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage, sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(v == NULL, ippStsMemAllocErr, pStorage);
    v = IPP_ALIGNED_PTR(v, CP_ML_KEM_ALIGNMENT);
    cp_byteDecode(v, d_v, c2);
    for (Ipp32u j = 0; j < 256; j++) {

        sts = cp_Decompress((Ipp16u*)&v->values[j], v->values[j], d_v);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }

    /* 5: s` <- cp_byteDecode_{12}(dk_{pke}) */
    Ipp16sPoly* s =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage,
                                             k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(s == NULL, ippStsMemAllocErr, pStorage);
    s = IPP_ALIGNED_PTR(s, CP_ML_KEM_ALIGNMENT);

    for (Ipp8u i = 0; i < k; i++) {
        cp_byteDecode(&s[i], 12, pPKE_DecKey + 384 * i);
    }

    /* 6: w <- v` - cp_NTT^{-1}(s`^{T} * cp_NTT(u`)) */
    Ipp16sPoly* w =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage, sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(w == NULL, ippStsMemAllocErr, pStorage);
    w = IPP_ALIGNED_PTR(w, CP_ML_KEM_ALIGNMENT);

    cp_NTT(&u[0]);
    cp_multiplyNTT(&s[0], &u[0], w);
    for (Ipp8u i = 1; i < k; i++) {
        cp_NTT(&u[i]);
        Ipp16sPoly tmpPoly;
        cp_multiplyNTT(&s[i], &u[i], &tmpPoly);
        cp_polyAdd(&tmpPoly, w, w);
    }
    cp_inverseNTT(w);
    cp_polySub(v, w, w);

    /* 7: m <- cp_byteEncode_{1}(Compress_{1}(w)) */
    for (Ipp32u j = 0; j < 256; j++) {
        sts = cp_Compress((Ipp16u*)&w->values[j], w->values[j], 1);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
    sts = cp_byteEncode(message, 1, w);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    /* Release locally used storage */
    /* clang-format off */
    sts  = cp_mlkemStorageRelease(pStorage, // Ipp16sPoly u[k]
                                  k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT); 
    sts |= cp_mlkemStorageRelease(pStorage, // Ipp16sPoly v
                                  sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    sts |= cp_mlkemStorageRelease(pStorage, // Ipp16sPoly s[k]
                                  k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    sts |= cp_mlkemStorageRelease(pStorage, // Ipp16sPoly w
                                  sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    /* clang-format on */

    return sts;
}
