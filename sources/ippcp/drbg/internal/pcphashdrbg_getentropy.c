/*************************************************************************
* Copyright (C) 2026 Intel Corporation
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

#include "owndefs.h"
#include "owncp.h"
#include "drbg/pcphashdrbg.h"
#include "drbg/pcphashdrbg_entropy_input.h"
#include "pcpbnumisc.h"
#include "pcpprng.h"

/*
 * Obtains entropyInput either by calling the callback function (if it isn't NULL) or by RDSEED
 *
 * Input parameters:
 *  minEntropyInBits             Minimum number bits of entropy
 *  predictionResistanceRequest
 *  pEntrInputCtx                Pointer to the Entropy input context
 *
 * Output parameters:
 *  pEntrInputBitsLen    Length of the buffer containing the entropy input
 *                       (*shall* be equal to or greater than min_length bits, and less
 *                        than or equal to max_length bits)
 *
 * NIST.SP.800-90C Section 8 "DRBG Construction"
*/

/* The function call is:
    (status, entropy_input) = Get_entropy_input(min_entropy, min_length,
                                                max_length, prediction_resistance_request)
    Since min_length = min_entropy, the second parameter for callback function is omitted
*/

// Minimum length of the entropyInput is equal to:
// - sec.strength + ½ sec.strength, if the function is invoked during Instantiating
// - sec.strength, if the function is invoked during Reseeding

/* clang-format off */
IPP_OWN_DEFN(IppStatus,
             cpHashDRBG_GetEntropyInput,
             (const int minEntropyInBits,
              const int predictionResistanceRequest,
              int* pEntrInputBitsLen,
              IppsHashDRBG_EntropyInputCtx* pEntrInputCtx))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;
    if (NULL == pEntrInputCtx->getEntropyInput) {
        /* use RDSEED as the primary source of random numbers */
        sts = ippsTRNGenRDSEED((Ipp32u*)pEntrInputCtx->entropyInput,
                               pEntrInputCtx->entrInputBufBitsLen,
                               NULL);
        /* use RDRAND if RDSEED instruction isn't support or random bit sequence can't be generated */
        if (ippStsNotSupportedModeErr == sts || ippStsErr == sts) {
            sts = ippsPRNGenRDRAND((Ipp32u*)pEntrInputCtx->entropyInput,
                                   pEntrInputCtx->entrInputBufBitsLen,
                                   NULL);
        }
        if (ippStsNoErr != sts) {
            return sts;
        }

        *pEntrInputBitsLen = pEntrInputCtx->entrInputBufBitsLen;
    } else {
        sts = pEntrInputCtx->getEntropyInput(pEntrInputCtx->entropyInput,
                                             pEntrInputBitsLen,
                                             minEntropyInBits,
                                             pEntrInputCtx->entrInputBufBitsLen,
                                             predictionResistanceRequest);
        if (ippStsNoErr != sts) {
            return sts;
        }

        /* entrInputBitsLen < (sec.strength + sec.strength/2)
           1) According to the NIST.SP.800-90Ar1 Table 2: "Definitions for Hash-Based DRBG Mechanisms"
              required minimum entropy for instantiate equals to securityStrength.
           2) According to the NIST.SP.800-90Ar1 Section 8.6.7 "Nonce", the nonce shall be either:
              a. A value with at least (security_strength/2) bits of entropy, or
              b. A value that is expected to repeat no more often than a (security_strength/2)-bit
                 random string would be expected to repeat */
        if ((*pEntrInputBitsLen < minEntropyInBits) ||
            (*pEntrInputBitsLen > pEntrInputCtx->entrInputBufBitsLen)) {
            return ippStsOutOfRangeErr;
        }
    }

    return sts;
}
