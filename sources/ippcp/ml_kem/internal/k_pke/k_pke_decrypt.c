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
#include "stateless_pqc/ml_kem_internal/ml_kem.h"
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

    /* Allocate memory for temporary objects */
    CP_ML_ALLOCATE_ALIGNED_POLYVEC(u, k, pStorage)
    CP_ML_ALLOCATE_ALIGNED_POLY(v, pStorage)
    CP_ML_ALLOCATE_ALIGNED_POLYVEC(s, k, pStorage)
    CP_ML_ALLOCATE_ALIGNED_POLY(w, pStorage)

    /* 1: c1 <- c[0 : 32*d_{u}*k] */
    Ipp8u* c1 = (Ipp8u*)ciphertext;
    /* 2: c2 <- c[32*d_{u}*k : 32(d_{u}*k + d_{v})] */
    Ipp8u* c2 = c1 + (32 * d_u * k);

    /* 3: u` <- Decompress_{d_{u}}(cp_byteDecode_{d_{u}}(c1)) */
    for (Ipp8u i = 0; i < k; i++) {
        sts = cp_byteDecode(&u[i], d_u, c1 + i * 32 * d_u, 32 * d_u * (k - i));
        IPP_BADARG_RET((sts != ippStsNoErr), sts);

        for (Ipp32u j = 0; j < 256; j++) {
            sts = cp_Decompress((Ipp16u*)&u[i].values[j], u[i].values[j], d_u);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }
    }

    /* 4: v` <- Decompress_{d_{v}}(cp_byteDecode_{d_{v}}(c2)) */
    sts = cp_byteDecode(v, d_v, c2, 32 * d_v);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    for (Ipp32u j = 0; j < 256; j++) {
        sts = cp_Decompress((Ipp16u*)&v->values[j], v->values[j], d_v);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }

    /* 5: s` <- cp_byteDecode_{12}(dk_{pke}) */
    for (Ipp8u i = 0; i < k; i++) {
        sts = cp_byteDecode(&s[i], 12, pPKE_DecKey + 384 * i, 384 * (k - i));
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }

    /* 6: w <- v` - cp_NTT^{-1}(s`^{T} * cp_NTT(u`)) */
    cp_NTT(&u[0]);
    cp_multiplyNTT(&s[0], &u[0], w);
    CP_ML_ALLOCATE_ALIGNED_POLY(tmpPoly, pStorage)
    for (Ipp8u i = 1; i < k; i++) {
        cp_NTT(&u[i]);
        cp_multiplyNTT(&s[i], &u[i], tmpPoly);
        cp_polyAdd(tmpPoly, w, w);
    }
    CP_ML_RELEASE_ALIGNED_POLY(pStorage, sts) // Ipp16sPoly tmpPoly
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
    CP_ML_RELEASE_ALIGNED_POLYVEC(k, pStorage, sts) // Ipp16sPoly u[k]
    CP_ML_RELEASE_ALIGNED_POLY(pStorage, sts)       // Ipp16sPoly v
    CP_ML_RELEASE_ALIGNED_POLYVEC(k, pStorage, sts) // Ipp16sPoly s[k]
    CP_ML_RELEASE_ALIGNED_POLY(pStorage, sts)       // Ipp16sPoly w

    return sts;
}
