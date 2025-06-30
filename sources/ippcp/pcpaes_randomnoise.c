/*************************************************************************
* Copyright (C) 2022 Intel Corporation
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
//
//  Purpose:
//     AES noise function
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpaesm.h"
#include "pcpbnumisc.h"
#include "pcptool.h"
#include "pcpprng.h"

/*F*
//    Name: cpAESRandomNoise
//
// Purpose: AES Random Noise
//
// Returns:                Reason:
//    ippStsNullPtrErr           pRndValue == NULL
//    ippStsLengthErr            29 < nBits > 32
//    ippStsScaleRangeErr        noiseRate > 1
//                               (MISTLETOE3_MAX_CHUNK_SIZE > MISTLETOE3_TARGET_SIZE - invalid)
//    ippStsNotSupportedModeErr  Mistletoe3 mitigation isn't applicable for current CPU
//                               (no support of Intel® Advanced Encryption Standard New Instructions (Intel® AES-NI) or
//                               vector extensions of Intel® AES-NI)
//    ippStsErr                  random bit sequence can't be generated
//    ippStsNoErr                no errors
//
// Parameters:
//    rndFunc     external random generator
//    nBits       number of bits that should be taken
//                from generated 32-bit random value
//    noiseRate   probability of refreshing the random
//                number pRndValue in the context
//    pRndValue   pointer to random number value from previous noise injection
//
*F*/

/* clang-format off */
IPP_OWN_DEFN(IppStatus, cpAESRandomNoise, (IppBitSupplier rndFunc,
                                           Ipp32u nBits,
                                           Ipp64f noiseRate,
                                           Ipp32u *pRndValue))
/* clang-format on */
{
#if (_AES_PROB_NOISE == _FEATURE_ON_)
    /* test that pRndValue pointer isn't NULL */
    IPP_BAD_PTR1_RET(pRndValue);

    /* test nBits and noiseRate values */
    IPP_BADARG_RET(nBits < 29 || nBits > 32, ippStsLengthErr);
    IPP_BADARG_RET((noiseRate > 1), ippStsScaleRangeErr);

    Ipp32u rand      = 0;
    IppStatus status = ippStsNoErr;

    IppsPRNGState Ctx;
    IppsPRNGState* pCtx = NULL;

    /* Use internal PRNG implementations if no external random source provided */
    if (NULL == rndFunc) {
        if (IsFeatureEnabled(ippCPUID_RDRAND))
            rndFunc = ippsPRNGenRDRAND;
        else // RDRAND feature isn't available
        {
            pCtx = &Ctx;
            ippsPRNGInit(160, pCtx);
            rndFunc = ippsPRNGen;
        }
    }

    Ipp32u ctxRand = *pRndValue;

    /* Get the threshold to generate random noise */
    const Ipp32u randMax  = (Ipp32u)(-1);
    Ipp32u noiseThreshold = (Ipp32u)((Ipp64f)randMax * noiseRate);

    /* Get a random value, which is used to decide whether a new random should be
    * generated. This allows generate random latency with probability */
    status = rndFunc(&rand, 32, pCtx);

    /* Check if new rand value required */
    if ((ippStsNoErr == status) && ((rand < noiseThreshold) || (ctxRand == 0))) {
        status = rndFunc(&ctxRand, (int)nBits, pCtx);
        if (ippStsNoErr == status) {
            /* Write back a new random */
            *pRndValue = ctxRand;
        }
    }

    /* Scale down based on noise rate */
    rand = (Ipp32u)((Ipp64f)ctxRand * noiseRate);

    if (ippStsNoErr == status) {
        _ippcpDelay(rand);
    }

    return status;
#else
    /* To remove MSVC warning C4100: 'XXX': unreferenced formal parameter*/
    IPP_UNREFERENCED_PARAMETER(rndFunc);
    IPP_UNREFERENCED_PARAMETER(nBits);
    IPP_UNREFERENCED_PARAMETER(noiseRate);
    IPP_UNREFERENCED_PARAMETER(pRndValue);

    return ippStsNotSupportedModeErr;
#endif /* #if (_AES_PROB_NOISE == _FEATURE_ON_) */
}
