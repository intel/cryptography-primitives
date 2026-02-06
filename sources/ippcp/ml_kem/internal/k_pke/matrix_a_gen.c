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

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"
#include "stateless_pqc/ml_kem_internal/ml_kem.h"
#include "hash/pcphash_rmf.h"
#include "hash/sha3/sha3_stuff.h"

/*
 * Algorithm 7: Takes a 32-byte seed and two indices as input and outputs a pseudorandom element of T_{q}
 */
#if (_IPP32E >= _IPP32E_K0)
/*
 * cp_SampleNTT_MB4()
 * 
 * Input:  B1         - byte array in B^{34}, buffer #1.
 *         B2         - byte array in B^{34}, buffer #2.
 *         B3         - byte array in B^{34}, buffer #3.
 *         B4         - byte array in B^{34}, buffer #4.
 *         numBuffers - number of buffers to be processed (up to 4).
 *         mlkemCtx   - pointer to state.
 * Output: polyA      - pointer to the numBuffers polynomials Z_{q}^{256} with sampled values.
 */
#define CP_ML_KEM_SAMPLENTT_BUFF_SIZE (258)
/* clang-format off */
IPPCP_INLINE IppStatus cp_SampleNTT_MB4(Ipp16sPoly* polyA, const Ipp8u B1[34], const Ipp8u B2[34],
                                          const Ipp8u B3[34], const Ipp8u B4[34], const Ipp32s numBuffers,
                                          IppsMLKEMState* mlkemCtx)
/* clang-format on */
{
    /* Prepare the multi-buffer hash state */
    Ipp8u state_buffer_mb4[STATE_x4_SIZE];
    cpSHA3_SHAKE128Ctx_mb4 state_mb4;
    state_mb4.ctx = state_buffer_mb4;

    /* Update hash state */
    cp_SHA3_SHAKE128_InitMB4(&state_mb4);
    cp_SHA3_SHAKE128_AbsorbMB4(&state_mb4, B1, B2, B3, B4, 34);
    cp_SHA3_SHAKE128_FinalizeMB4(&state_mb4);

    /* The hash squeeze loop for up to 4 buffers */
    Ipp32u buffer_bytes_used = 0;
    Ipp8u arrC[CP_ML_KEM_NUM_BUFFERS][CP_ML_KEM_SAMPLENTT_BUFF_SIZE];
    /* Squeeze the first big block unconditionally */
    cp_SHA3_SHAKE128_SqueezeMB4(arrC[0],
                                arrC[1],
                                arrC[2],
                                arrC[3],
                                CP_ML_KEM_SAMPLENTT_BUFF_SIZE,
                                &state_mb4);

    /* Looping index is separate for each buffer */
    Ipp16u j[CP_ML_KEM_NUM_BUFFERS] = { 0, 0, 0, 0 };
    while ((((numBuffers - 1) >= 0) && (j[0] < 256)) || (((numBuffers - 2) >= 0) && (j[1] < 256)) ||
           (((numBuffers - 3) >= 0) && (j[2] < 256)) || (((numBuffers - 4) >= 0) && (j[3] < 256))) {

        if (buffer_bytes_used >= CP_ML_KEM_SAMPLENTT_BUFF_SIZE) {
            cp_SHA3_SHAKE128_SqueezeMB4(arrC[0],
                                        arrC[1],
                                        arrC[2],
                                        arrC[3],
                                        CP_ML_KEM_SAMPLENTT_BUFF_SIZE,
                                        &state_mb4);
            buffer_bytes_used = 0;
        }

        Ipp16u d1[CP_ML_KEM_NUM_BUFFERS];
        d1[0] = arrC[0][buffer_bytes_used + 0] + 256 * (arrC[0][buffer_bytes_used + 1] % 16);
        d1[1] = arrC[1][buffer_bytes_used + 0] + 256 * (arrC[1][buffer_bytes_used + 1] % 16);
        d1[2] = arrC[2][buffer_bytes_used + 0] + 256 * (arrC[2][buffer_bytes_used + 1] % 16);
        d1[3] = arrC[3][buffer_bytes_used + 0] + 256 * (arrC[3][buffer_bytes_used + 1] % 16);

        Ipp16u d2[CP_ML_KEM_NUM_BUFFERS];
        d2[0] = arrC[0][buffer_bytes_used + 1] / 16 + 16 * arrC[0][buffer_bytes_used + 2];
        d2[1] = arrC[1][buffer_bytes_used + 1] / 16 + 16 * arrC[1][buffer_bytes_used + 2];
        d2[2] = arrC[2][buffer_bytes_used + 1] / 16 + 16 * arrC[2][buffer_bytes_used + 2];
        d2[3] = arrC[3][buffer_bytes_used + 1] / 16 + 16 * arrC[3][buffer_bytes_used + 2];

        // Fill elements of up to 4 polynomials
        for (Ipp32s buf = 0; buf < numBuffers; buf++) {
            if ((d1[buf] < mlkemCtx->params.q) && (j[buf] < 256)) {
                polyA[buf].values[j[buf]] = (Ipp16s)d1[buf];
                j[buf]++;
            }
            if ((d2[buf] < mlkemCtx->params.q) && (j[buf] < 256)) {
                polyA[buf].values[j[buf]] = (Ipp16s)d2[buf];
                j[buf]++;
            }
        }
        buffer_bytes_used += 3;
    }

    return ippStsNoErr;
}
#undef CP_ML_KEM_SAMPLENTT_BUFF_SIZE

#else
/*
 * cp_SampleNTT()
 *
 * Input:  B        - byte array in B^{34}.
 *         mlkemCtx - pointer to state.
 * Output: polyA    - polynomial Z_{q}^{256} with sampled values.
 */
/* clang-format off */
IPPCP_INLINE IppStatus cp_SampleNTT(Ipp16sPoly* polyA, const Ipp8u B[34], IppsMLKEMState* mlkemCtx)
/* clang-format on */
{
    IppStatus sts             = ippStsNoErr;
    _cpMLKEMStorage* pStorage = &mlkemCtx->storage;

    const IppsHashMethod* hash_method = ippsHashMethod_SHAKE128(3 * 8 * 256);
    int hash_size                     = 0;
    sts                               = ippsHashGetSizeOptimal_rmf(&hash_size, hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    IppsHashState_rmf* hash_state =
        (IppsHashState_rmf*)cp_mlStorageAllocate(pStorage, hash_size + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(hash_state == NULL, ippStsMemAllocErr, pStorage);
    hash_state = IPP_ALIGNED_PTR(hash_state, CP_ML_KEM_ALIGNMENT);
    sts        = ippsHashInit_rmf(hash_state, hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    sts = ippsHashUpdate_rmf(B, 34, hash_state);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    for (Ipp16u j = 0; (j < 256) && (sts == ippStsNoErr);) {
        Ipp8u arrC[3];
        sts = ippsHashSqueeze_rmf(arrC, 3, hash_state);

        Ipp16u d1 = arrC[0] + 256 * (arrC[1] % 16);
        Ipp16u d2 = arrC[1] / 16 + 16 * arrC[2];
        if (d1 < mlkemCtx->params.q) {
            polyA->values[j] = (Ipp16s)d1;
            j++;
        }
        if ((d2 < mlkemCtx->params.q) && (j < 256)) {
            polyA->values[j] = (Ipp16s)d2;
            j++;
        }
    }

    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage, hash_size + CP_ML_KEM_ALIGNMENT); // hash_state

    return sts;
}
#endif /* #if (_IPP32E >= _IPP32E_K0) */

/*
 * Generates the matrix A for the ML KEM scheme.
 *
 * Input:  rho_j_i    - byte array of size 34 bytes, where the first 32 bytes are the seed
 *                      and the last two bytes are indices i and j
 *         matrixType - flag reflecting the type of matrix to be generated
 *         mlkemCtx   - pointer to state.
 * Output: matrixA - output pointer to the matrix A of size k*k elements
 *
 * Note:  cp_SampleNTT is the main computation kernel.
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_matrixAGen,
            (Ipp16sPoly* matrixA, Ipp8u rho_j_i_0[34], matrixAGenType matrixType, IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;
    const Ipp8u k = mlkemCtx->params.k;

/* Multi-buffer approach */
#if (_IPP32E >= _IPP32E_K0)
    /* Prepare rho for the multi-buffer processing */
    Ipp8u rho_j_i_1[34];
    Ipp8u rho_j_i_2[34];
    Ipp8u rho_j_i_3[34];
    CopyBlock(rho_j_i_0, rho_j_i_1, 32);
    CopyBlock(rho_j_i_0, rho_j_i_2, 32);
    CopyBlock(rho_j_i_0, rho_j_i_3, 32);

    Ipp32u writeIdx     = (matrixType == matrixAOrigin) ? 32 : 33;
    rho_j_i_0[writeIdx] = 0;
    rho_j_i_1[writeIdx] = 1;
    rho_j_i_2[writeIdx] = 2;
    rho_j_i_3[writeIdx] = 3;

    // Change the index for the processing in the loop
    writeIdx = (matrixType == matrixAOrigin) ? 33 : 32;

    for (Ipp8u i = 0; i < k; i++) {
        rho_j_i_0[writeIdx]    = i;
        rho_j_i_1[writeIdx]    = i;
        rho_j_i_2[writeIdx]    = i;
        rho_j_i_3[writeIdx]    = i;
        Ipp16sPoly* pMatrixAij = &matrixA[i * k];

        /* A[i, j] <- cp_SampleNTT_MB4(rho||i||j) */
        sts = cp_SampleNTT_MB4(pMatrixAij, rho_j_i_0, rho_j_i_1, rho_j_i_2, rho_j_i_3, k, mlkemCtx);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
#else
    for (Ipp8u i = 0; i < k; i++) {
        for (Ipp8u j = 0; j < k; j++) {
            if (matrixType == matrixAOrigin) {
                rho_j_i_0[32] = j;
                rho_j_i_0[33] = i;
            } else { // matrixType == matrixATransposed
                rho_j_i_0[32] = i;
                rho_j_i_0[33] = j;
            }
            Ipp16sPoly* pMatrixAij = &matrixA[i * k + j];

            /* A[i, j] <- cp_SampleNTT(rho||i||j) */
            sts = cp_SampleNTT(pMatrixAij, rho_j_i_0, mlkemCtx);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }
    }

#endif /* #if (_IPP32E >= _IPP32E_K0) */

    return sts;
}
