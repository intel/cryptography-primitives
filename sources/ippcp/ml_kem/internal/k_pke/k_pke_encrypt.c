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
 * Level 2(K-PKE) function cp_KPKE_Encrypt
 */

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"
#include "ml_kem_internal/ml_kem.h"
#include "hash/pcphash_rmf.h"

/*
 * Uses the encryption key to encrypt a plaintext message using the randomness r.
 *
 *      ciphertext - output pointer to the generated ciphertext of size 32*(d_{u}*k+d_{v})) bytes
 *      inpEncKey  - input pointer to the encryption key of size 384*k + 32 bytes
 *      m          - input parameter with the generated plaintext message of size 32 bytes
 *      r_N        - input parameter with the generated randomness of size 32 bytes + 1 byte to store N
 *      mlkemCtx   - input pointer to the ML KEM context
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_KPKE_Encrypt, (Ipp8u * ciphertext,
                                          const Ipp8u* inpEncKey,
                                          const Ipp8u m[CP_RAND_DATA_BYTES],
                                          Ipp8u r_N[CP_RAND_DATA_BYTES + 1],
                                          IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    IppStatus sts             = ippStsNoErr;
    const Ipp8u k             = mlkemCtx->params.k;
    const Ipp16u d_u          = mlkemCtx->params.d_u;
    const Ipp8u d_v           = mlkemCtx->params.d_v;
    const Ipp8u eta1          = mlkemCtx->params.eta1;
    const Ipp8u eta2          = mlkemCtx->params.eta2;
    _cpMLKEMStorage* pStorage = &mlkemCtx->storage;

    /* 1: N <- 0, iterated in the range [0, 7) */
    Ipp8u N = 0;

    /* 2: Decode t <- cp_byteDecode_{12}(ekPKE[0 : 384*k]), t is an element of (Z_{q}^{256})^{k} */
    Ipp16sPoly* t =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage,
                                             k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(t == NULL, ippStsMemAllocErr, pStorage);
    t = IPP_ALIGNED_PTR(t, CP_ML_KEM_ALIGNMENT);
    for (Ipp8u i = 0; i < k; i++) {
        cp_byteDecode(&t[i], 12, inpEncKey + 384 * i);
    }

    /* 3: rho <- ekPKE[384*k : 384*k+32] */
    Ipp8u rho_j_i[34];
    CopyBlock(inpEncKey + 384 * k, rho_j_i, 32);
    /* 4-8: Re-generate matrix A */
    Ipp16sPoly* matrixA = (Ipp16sPoly*)(mlkemCtx->pA);
    cp_matrixAGen(matrixA, rho_j_i, mlkemCtx);

    /* Generate vectors y and e_1 */

    /* 9-12: Generate vector y */
    Ipp16sPoly* vectorY =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage,
                                             k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(vectorY == NULL, ippStsMemAllocErr, pStorage);
    vectorY = IPP_ALIGNED_PTR(vectorY, CP_ML_KEM_ALIGNMENT);
    cp_polyVecGen(vectorY, r_N, &N, eta1, mlkemCtx, nttTransform);

    /* 13-16: Generate vector e1 */
    Ipp16sPoly* vectorE1 =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage,
                                             k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(vectorE1 == NULL, ippStsMemAllocErr, pStorage);
    vectorE1 = IPP_ALIGNED_PTR(vectorE1, CP_ML_KEM_ALIGNMENT);
    cp_polyVecGen(vectorE1, r_N, &N, eta2, mlkemCtx, noNttTransform);

    /* 17: Generate polynomial e2 */
    Ipp16sPoly* polyE2 =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage, sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(polyE2 == NULL, ippStsMemAllocErr, pStorage);
    polyE2 = IPP_ALIGNED_PTR(polyE2, CP_ML_KEM_ALIGNMENT);
    cp_polyGen(polyE2, r_N, &N, eta2, mlkemCtx, noNttTransform);

    /* 19: u <- cp_NTT^{-1}(A^{T} * y`) + e1 */
    Ipp16sPoly* u =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage,
                                             k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(u == NULL, ippStsMemAllocErr, pStorage);
    u = IPP_ALIGNED_PTR(u, CP_ML_KEM_ALIGNMENT);
    for (Ipp8u i = 0; i < k; i++) {
        cp_multiplyNTT(CP_MATRIX_A_GET_I_J(matrixA, 0, i), &vectorY[0], &u[i]);

        for (Ipp8u j = 1; j < k; j++) {
            Ipp16sPoly tmpPoly;
            cp_multiplyNTT(CP_MATRIX_A_GET_I_J(matrixA, j, i), &vectorY[j], &tmpPoly);
            cp_polyAdd(&tmpPoly, &u[i], &u[i]);
        }
        cp_inverseNTT(&u[i]);
        cp_polyAdd(&vectorE1[i], &u[i], &u[i]);
    }

    /* 20: mu <- Decompress_{1}(cp_byteDecode_{1}(m)) */
    Ipp16sPoly* polyMu =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage, sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(polyMu == NULL, ippStsMemAllocErr, pStorage);
    polyMu = IPP_ALIGNED_PTR(polyMu, CP_ML_KEM_ALIGNMENT);

    cp_byteDecode(polyMu, 1, m);
    for (Ipp32u i = 0; i < 256; i++) {
        sts = cp_Decompress((Ipp16u*)&polyMu->values[i], polyMu->values[i], 1);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }

    /* 21: v <- cp_NTT^{-1}(t^{T} * y) + e2 + mu */
    Ipp16sPoly* v =
        (Ipp16sPoly*)cp_mlkemStorageAllocate(pStorage, sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(v == NULL, ippStsMemAllocErr, pStorage);
    v = IPP_ALIGNED_PTR(v, CP_ML_KEM_ALIGNMENT);
    cp_multiplyNTT(&t[0], &vectorY[0], v);
    for (Ipp8u j = 1; j < k; j++) {
        Ipp16sPoly tmpPoly;
        cp_multiplyNTT(&t[j], &vectorY[j], &tmpPoly);
        cp_polyAdd(&tmpPoly, v, v);
    }
    cp_inverseNTT(v);
    cp_polyAdd(polyE2, v, v);
    cp_polyAdd(polyMu, v, v);

    /* Set up c1 and c2 pointers */
    Ipp8u* c1 = ciphertext;
    Ipp8u* c2 = ciphertext + (32 * d_u * k);

    /* 22: c1 <- cp_byteEncode_{d_{u}}(Compress_{d_{u}}(u)) */
    for (Ipp8u i = 0; i < k; i++) {
        for (Ipp32u j = 0; j < 256; j++) {
            sts = cp_Compress((Ipp16u*)&u[i].values[j], u[i].values[j], d_u);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }
        sts = cp_byteEncode(c1 + i * 32 * d_u, d_u, &u[i]);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }

    /* 23: c2 <- cp_byteEncode_{d_{v}}(Compress_{d_{v}}(v)) */
    for (Ipp32u j = 0; j < 256; j++) {
        sts = cp_Compress((Ipp16u*)&v->values[j], v->values[j], d_v);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
    sts = cp_byteEncode(c2, d_v, v);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    /* Release locally used storage */
    /* clang-format off */
    sts  = cp_mlkemStorageRelease(pStorage, // Ipp16sPoly t[k]
                                  k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    sts |= cp_mlkemStorageRelease(pStorage, // Ipp16sPoly vectorY[k], vectorE1[k]
                                  2 * (k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT));
    sts |= cp_mlkemStorageRelease(pStorage, // Ipp16sPoly polyE2
                                  sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    sts |= cp_mlkemStorageRelease(pStorage, // Ipp16sPoly u[k]
                                  k * sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    sts |= cp_mlkemStorageRelease(pStorage, // Ipp16sPoly polyMu
                                  sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    sts |= cp_mlkemStorageRelease(pStorage, // Ipp16sPoly v
                                  sizeof(Ipp16sPoly) + CP_ML_KEM_ALIGNMENT);
    /* clang-format on */

    return sts;
}
