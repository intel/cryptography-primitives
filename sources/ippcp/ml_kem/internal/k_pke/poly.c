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
 * Polynomial generation functions definition
 */

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"
#include "ml_kem_internal/ml_kem.h"
#include "hash/sha3/sha3_stuff.h"

#if (_IPP32E >= _IPP32E_K0)
/*
 * Multi-buffer kernel generating up to 4 Ipp16sPoly polynomials at once.
 *
 * Input:  inRand_N      - buffer with r data, the last byte is used to store N.
 *         N             - pointer to the value of N, will be incremented in-place.
 *         eta           - parameter defining the distribution to sample from.
 *         transformFlag - flag to indicate whether to apply NTT transform to each generated polynomial.
 *         numBuffers    - number of buffers to be processed (up to 4).
 * Output: pOutPoly      - the generated polynomials (total number equals to numBuffers).
 *
 */
IPPCP_INLINE IppStatus cp_polyGenInternal_MB4(Ipp16sPoly* pOutPoly,
                                              Ipp8u inRand_N[CP_RAND_DATA_BYTES + 1],
                                              Ipp8u* N,
                                              const Ipp8u eta,
                                              nttTransformFlag transformFlag,
                                              Ipp32s numBuffers)
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;

    /* Allocate and fill 4 buffers of the data with the input passed in inRand_N */
    Ipp8u inRand_N_0[CP_RAND_DATA_BYTES + 1];
    Ipp8u inRand_N_1[CP_RAND_DATA_BYTES + 1];
    Ipp8u inRand_N_2[CP_RAND_DATA_BYTES + 1];
    Ipp8u inRand_N_3[CP_RAND_DATA_BYTES + 1];
    CopyBlock(inRand_N, inRand_N_0, CP_RAND_DATA_BYTES);
    CopyBlock(inRand_N, inRand_N_1, CP_RAND_DATA_BYTES);
    CopyBlock(inRand_N, inRand_N_2, CP_RAND_DATA_BYTES);
    CopyBlock(inRand_N, inRand_N_3, CP_RAND_DATA_BYTES);
    inRand_N_0[32] = *N;
    inRand_N_1[32] = *N + 1;
    inRand_N_2[32] = *N + 2;
    inRand_N_3[32] = *N + 3;

    /* Outputs of the PRF function */
    Ipp8u prfOutput_0[CP_ML_KEM_ETA_MAX * 64];
    Ipp8u prfOutput_1[CP_ML_KEM_ETA_MAX * 64];
    Ipp8u prfOutput_2[CP_ML_KEM_ETA_MAX * 64];
    Ipp8u prfOutput_3[CP_ML_KEM_ETA_MAX * 64];

    /* SHAKE256 multi-buffer processing */
    Ipp8u state_buffer_mb4[STATE_x4_SIZE];
    cpSHA3_SHAKE256Ctx_mb4 state_mb4;
    state_mb4.ctx = state_buffer_mb4;

    cp_SHA3_SHAKE256_InitMB4(&state_mb4);
    cp_SHA3_SHAKE256_AbsorbMB4(&state_mb4,
                               inRand_N_0,
                               inRand_N_1,
                               inRand_N_2,
                               inRand_N_3,
                               CP_RAND_DATA_BYTES + 1);
    cp_SHA3_SHAKE256_FinalizeMB4(&state_mb4);
    cp_SHA3_SHAKE256_SqueezeMB4(prfOutput_0,
                                prfOutput_1,
                                prfOutput_2,
                                prfOutput_3,
                                64 * eta,
                                &state_mb4);

    /* Final processing of the required amount of the buffers */
    switch (numBuffers) {
    case 4: {
        sts = cp_samplePolyCBD(&pOutPoly[3], prfOutput_3, eta);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        (*N)++;
        if (transformFlag == nttTransform) {
            /* 18: y` <- cp_NTT(𝐲) */
            cp_NTT(&pOutPoly[3]);
        }
        IPPCP_FALLTHROUGH;
    }
    case 3: {
        sts = cp_samplePolyCBD(&pOutPoly[2], prfOutput_2, eta);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        (*N)++;
        if (transformFlag == nttTransform) {
            /* 18: y` <- cp_NTT(𝐲) */
            cp_NTT(&pOutPoly[2]);
        }
        IPPCP_FALLTHROUGH;
    }
    case 2: {
        sts = cp_samplePolyCBD(&pOutPoly[1], prfOutput_1, eta);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        (*N)++;
        if (transformFlag == nttTransform) {
            /* 18: y` <- cp_NTT(𝐲) */
            cp_NTT(&pOutPoly[1]);
        }
        IPPCP_FALLTHROUGH;
    }
    case 1: {
        sts = cp_samplePolyCBD(&pOutPoly[0], prfOutput_0, eta);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        (*N)++;
        if (transformFlag == nttTransform) {
            /* 18: y` <- cp_NTT(𝐲) */
            cp_NTT(&pOutPoly[0]);
        }
        break;
    }
    default: {
        return ippStsBadArgErr;
    }
    }

    return sts;
}
#endif /* #if (_IPP32E >= _IPP32E_K0) */

/*
 * Common kernel generating a Ipp16sPoly polynomial.
 *
 * Input:  inRand_N      - buffer with r data, the last byte is used to store N.
 *         N             - pointer to the value of N, will be incremented in-place.
 *         eta           - parameter defining the distribution to sample from.
 *         mlkemCtx      - pointer to the ML KEM context.
 *         transformFlag - flag to indicate whether to apply NTT transform to each generated polynomial.
 * Output: pOutPoly      - the generated polynomial.
 *
 */
/* clang-format off */
IPPCP_INLINE IppStatus cp_polyGenInternal(Ipp16sPoly* pOutPoly,
                                            Ipp8u inRand_N[CP_RAND_DATA_BYTES + 1],
                                            Ipp8u* N,
                                            const Ipp8u eta,
                                            IppsMLKEMState* mlkemCtx,
                                            nttTransformFlag transformFlag)
/* clang-format on */
{
    IppStatus sts             = ippStsNoErr;
    _cpMLKEMStorage* pStorage = &mlkemCtx->storage;

    Ipp8u* prfOutput = cp_mlkemStorageAllocate(pStorage, eta * 64 + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(prfOutput == NULL, ippStsMemAllocErr, pStorage);
    prfOutput = IPP_ALIGNED_PTR(prfOutput, CP_ML_KEM_ALIGNMENT);

    inRand_N[32] = *N;
#if (_IPP32E >= _IPP32E_K0)
    cp_SHA3_SHAKE256_HashMessage(prfOutput, 64 * eta, inRand_N, 33);
#else
    sts = ippsHashMessage_rmf(inRand_N, 33, prfOutput, ippsHashMethod_SHAKE256(8 * 64 * eta));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
#endif /* #if (_IPP32E >= _IPP32E_K0) */

    sts = cp_samplePolyCBD(pOutPoly, prfOutput, eta);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    (*N)++;

    if (transformFlag == nttTransform) {
        /* 18: y` <- cp_NTT(𝐲) */
        cp_NTT(pOutPoly);
    }
    sts = cp_mlkemStorageRelease(pStorage, // Ipp8u prfOutput[eta * 64]
                                 eta * 64 + CP_ML_KEM_ALIGNMENT);

    return sts;
}

/*
 * Generates a vector of k Ipp16sPoly polynomials.
 *
 * Input:  inRand_N      - buffer with randomness data, the last byte is used to store N.
 *         N             - pointer to the value of N, will be incremented in-place.
 *         eta           - parameter defining the distribution to sample from.
 *         mlkemCtx      - pointer to the ML KEM context.
 *         transformFlag - flag to indicate whether to apply NTT transform to each generated polynomial.
 * Output: pOutPolyVec   - the vector of generated polynomials.
 *
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_polyVecGen, (Ipp16sPoly* pOutPolyVec,
                                        Ipp8u inRand_N[CP_RAND_DATA_BYTES + 1],
                                        Ipp8u* N,
                                        const Ipp8u eta,
                                        IppsMLKEMState* mlkemCtx,
                                        nttTransformFlag transformFlag))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;

#if (_IPP32E >= _IPP32E_K0)
    sts = cp_polyGenInternal_MB4(pOutPolyVec, inRand_N, N, eta, transformFlag, mlkemCtx->params.k);
#else
    for (Ipp8u i = 0; i < mlkemCtx->params.k && sts == ippStsNoErr; i++) {
        sts = cp_polyGenInternal(&pOutPolyVec[i], inRand_N, N, eta, mlkemCtx, transformFlag);
    }
#endif /* #if (_IPP32E >= _IPP32E_K0) */


    return sts;
}

/*
 * Generates a Ipp16sPoly polynomial.
 *
 * Input:  inRand_N      - buffer with randomness data, the last byte is used to store N.
 *         N             - pointer to the value of N, will be incremented in-place.
 *         eta           - parameter defining the distribution to sample from.
 *         mlkemCtx      - pointer to the ML KEM context.
 *         transformFlag - flag to indicate whether to apply NTT transform to each generated polynomial.
 * Output: pOutPolyVec   - the vector of generated polynomials.
 *
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_polyGen, (Ipp16sPoly* pOutPolyVec,
                                     Ipp8u inRand_N[CP_RAND_DATA_BYTES + 1],
                                     Ipp8u* N,
                                     const Ipp8u eta,
                                     IppsMLKEMState* mlkemCtx,
                                     nttTransformFlag transformFlag))
/* clang-format on */
{
    return cp_polyGenInternal(pOutPolyVec, inRand_N, N, eta, mlkemCtx, transformFlag);
}
