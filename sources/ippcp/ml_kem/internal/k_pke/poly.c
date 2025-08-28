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

/*
 * Generates a Ipp16sPoly polynomial.
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
IPP_OWN_DEFN(IppStatus, cp_polyGen, (Ipp16sPoly* pOutPoly,
                                     Ipp8u inRand_N[CP_RAND_DATA_BYTES + 1],
                                     Ipp8u* N,
                                     const Ipp8u eta,
                                     IppsMLKEMState* mlkemCtx,
                                     nttTransformFlag transformFlag))
/* clang-format on */
{
    IppStatus sts             = ippStsNoErr;
    _cpMLKEMStorage* pStorage = &mlkemCtx->storage;

    Ipp8u* prfOutput = cp_mlkemStorageAllocate(pStorage, eta * 64 + CP_ML_KEM_ALIGNMENT);
    CP_CHECK_FREE_RET(prfOutput == NULL, ippStsMemAllocErr, pStorage);
    prfOutput = IPP_ALIGNED_PTR(prfOutput, CP_ML_KEM_ALIGNMENT);

    inRand_N[32] = *N;
    sts = ippsHashMessage_rmf(inRand_N, 33, prfOutput, ippsHashMethod_SHAKE256(8 * 64 * eta));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
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

    for (Ipp8u i = 0; i < mlkemCtx->params.k && sts == ippStsNoErr; i++) {
        sts = cp_polyGen(&pOutPolyVec[i], inRand_N, N, eta, mlkemCtx, transformFlag);
    }

    return sts;
}
