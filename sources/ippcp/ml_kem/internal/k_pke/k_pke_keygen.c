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
 * Level 2(K-PKE) function cp_KPKE_KeyGen
 */

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"
#include "ml_kem_internal/ml_kem.h"
#include "hash/pcphash_rmf.h"

/*
 * Uses randomness to generate an encryption key and a corresponding decryption key.
 *      outEncKey  - output pointer to the encryption key of size 384*k + 32 bytes
 *      outDecKey  - output pointer to the decryption key of size 384*k
 *      d_k        - input parameter with the generated randomness of size 32 bytes + 1 byte for k
 *      mlkemCtx   - input pointer to the ML KEM context
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_KPKE_KeyGen, (Ipp8u* outEncKey,
                                         Ipp8u* outDecKey,
                                         const Ipp8u d_k[33],
                                         IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    IppStatus sts             = ippStsNoErr;
    const Ipp8u k             = mlkemCtx->params.k;
    const Ipp8u eta1          = mlkemCtx->params.eta1;
    _cpMLKEMStorage* pStorage = &mlkemCtx->storage;

    /* Allocate memory for temporary objects */
    CP_ML_KEM_ALLOCATE_ALIGNED_POLYVEC(vectorS, k, pStorage)
    CP_ML_KEM_ALLOCATE_ALIGNED_POLYVEC(vectorE, k, pStorage)
    CP_ML_KEM_ALLOCATE_ALIGNED_POLYVEC(t, k, pStorage)

    /* (rho,sigma) <- G(d||k) */
    // stores 32 bytes of rho, 32 bytes of sigma and 1 byte of N
    Ipp8u rho_sigma_N[65];
    Ipp8u* pRho     = rho_sigma_N;
    Ipp8u* pSigma_N = rho_sigma_N + 32;

    sts = ippsHashMessage_rmf(d_k, 33, rho_sigma_N, ippsHashMethod_SHA3_512());
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    // N is iterated in the range [0, 7)
    Ipp8u N = 0;

    /* Generate matrix A */
    Ipp8u rho_j_i[34];
    CopyBlock(pRho, rho_j_i, 32);
    Ipp16sPoly* matrixA = (Ipp16sPoly*)(mlkemCtx->pA); // vectors accessing pointer
    cp_matrixAGen(matrixA, rho_j_i, matrixAOrigin, mlkemCtx);

    /* Generate vector s */
    cp_polyVecGen(vectorS, pSigma_N, &N, eta1, mlkemCtx, nttTransform);

    /* Generate vector e */
    cp_polyVecGen(vectorE, pSigma_N, &N, eta1, mlkemCtx, nttTransform);

    /* t` = A` * s` + e` */
    CP_ML_KEM_ALLOCATE_ALIGNED_POLY(tmpPoly, pStorage)
    for (Ipp8u i = 0; i < k; i++) {
        cp_multiplyNTT(CP_MATRIX_A_GET_I_J(matrixA, i, 0), &vectorS[0], &t[i]);

        for (Ipp8u j = 1; j < k; j++) {
            cp_multiplyNTT(CP_MATRIX_A_GET_I_J(matrixA, i, j), &vectorS[j], tmpPoly);
            cp_polyAdd(tmpPoly, &t[i], &t[i]);
        }
        cp_polyAdd(&vectorE[i], &t[i], &t[i]);
    }
    CP_ML_KEM_RELEASE_ALIGNED_POLY(pStorage, sts) // Ipp16sPoly tmpPoly

    for (Ipp8u i = 0; i < k; i++) {
        sts = cp_byteEncode(outDecKey + i * 384, 12, &vectorS[i]);
        sts |= cp_byteEncode(outEncKey + i * 384, 12, &t[i]);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
    CopyBlock(pRho, outEncKey + 384 * k, 32);

    /* Release locally used storage */
    CP_ML_KEM_RELEASE_ALIGNED_POLYVEC(k, pStorage, sts) // Ipp16sPoly vectorS[k]
    CP_ML_KEM_RELEASE_ALIGNED_POLYVEC(k, pStorage, sts) // Ipp16sPoly vectorE[k]
    CP_ML_KEM_RELEASE_ALIGNED_POLYVEC(k, pStorage, sts) // Ipp16sPoly t[k]

    return sts;
}
