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
#include "ml_kem_internal/ml_kem.h"
#include "hash/pcphash_rmf.h"

/*
 * Algorithm 7: Takes a 32-byte seed and two indices as input and outputs a pseudorandom element of T_{q}
 * Input:  B        - byte array in B^{34}.
 *         mlkemCtx - pointer to state.
 * Output: polyA    - polynomial Z_{q}^{256} with sampled values.
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_SampleNTT,
            (Ipp16sPoly * polyA, const Ipp8u B[34], IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    IppStatus sts             = ippStsNoErr;
    _cpMLKEMStorage* pStorage = &mlkemCtx->storage;

    const IppsHashMethod* hash_method = ippsHashMethod_SHAKE128(3 * 8 * 256);
    int hash_size                     = 0;
    sts                               = ippsHashGetSizeOptimal_rmf(&hash_size, hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    IppsHashState_rmf* hash_state =
        (IppsHashState_rmf*)cp_mlkemStorageAllocate(pStorage, hash_size + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(hash_state == NULL, ippStsMemAllocErr, pStorage);
    hash_state = IPP_ALIGNED_PTR(hash_state, CP_ML_KEM_ALIGNMENT);

    sts = ippsHashInit_rmf(hash_state, hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    sts = ippsHashUpdate_rmf(B, 34, hash_state);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    /* Finalize the state for the squeeze below */
    cpFinalize_rmf(HASH_VALUE(hash_state),
                   HASH_BUFF(hash_state),
                   HASH_BUFFIDX(hash_state),
                   HASH_LENLO(hash_state),
                   HASH_LENHI(hash_state),
                   hash_method);

    int digestLenProcessed = 0;

    for (Ipp16u j = 0; j < 256;) {
        Ipp8u arrC[3];
        cpHashSqueeze(arrC, HASH_VALUE(hash_state), hash_method, 3, &digestLenProcessed);

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
    sts = cp_mlkemStorageRelease(pStorage, hash_size + CP_ML_KEM_ALIGNMENT); // hash_state

    return sts;
}

/*
 * Generates the matrix A for the ML KEM scheme.
 *
 * Input:  rho_j_i  - byte array of size 34 bytes, where the first 32 bytes are the seed
 *                    and the last two bytes are indices i and j
 *         mlkemCtx - pointer to state.
 * Output: matrixA - output pointer to the matrix A of size k*k elements
 *
 * Note:  cp_SampleNTT is the main computation kernel.
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_matrixAGen,
            (Ipp16sPoly * matrixA, Ipp8u rho_j_i[34], IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;
    const Ipp8u k = mlkemCtx->params.k;

    for (Ipp8u i = 0; i < k; i++) {
        for (Ipp8u j = 0; j < k; j++) {
            rho_j_i[32]            = j;
            rho_j_i[33]            = i;
            Ipp16sPoly* pMatrixAij = &matrixA[i * k + j];

            /* A[i, j] <- cp_SampleNTT(rho||i||j) */
            sts = cp_SampleNTT(pMatrixAij, rho_j_i, mlkemCtx);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }
    }

    return sts;
}
