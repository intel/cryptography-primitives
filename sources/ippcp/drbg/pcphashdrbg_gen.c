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
#include "pcptool.h"

/*
//    Name: ippsHashDRBG_Gen
//
// Purpose: Generates a pseudorandom unsigned 32-bit integer buffer of the specified bit length
//
// Returns:                     Reason:
//    ippStsNullPtrErr           pRand         == NULL
//                               pDrbgCtx      == NULL
//                               pEntrInputCtx == NULL
//                               cpHashDRBG_Gen returns this error if obtained entropyInput is NULL
//    ippStsContextMatchErr      If the DRBG identifier doesn't match
//                               If the Entropy input context identifier doesn't match
//    ippStsBadArgErr            Prediction resistance is requested, but predictionResistanceFlag has been set to 0
//                               nBits            < 1
//                               nBits            > Max number of bits per request
//                               addlInput        == NULL and addlInputBitsLen > 0 or
//                               addlInput        != NULL, but addlInputBitsLen == 0
//    ippStsOutOfRangeErr        addlInputBitsLen < 0 (if len exceeds MAX additional input length)
//                               cpHashDRBG_Gen returns this error if entrInputBitsLen is out of range
//    ippStsHashOperationErr     cpHashDRBG_Gen returns this error if sth goes wrong when hashing
//    ippStsNotSupportedModeErr  cpHashDRBG_Gen returns this error if the CPU doesn't support RDSEED or RDRAND
//    ippStsNoErr                No errors
//
// Parameters:
//    pRand                        Pointer to the output pseudorandom unsigned integer buffer
//    nBits                        Requested number of bits to be generated
//    requestedSecurityStrength    The security strength to be associated with the requested pseudorandom bits
//    predictionResistanceRequest  Indicates whether or not prediction resistance is to be provided
//                                 during the request (i.e., whether or not fresh entropy bits are required)
//    addlInput                    Pointer to the array containing additional input (optional)
//    addlInputBitsLen             Length of the addlInput in bits (may be zero)
//    pEntrInputCtx                Pointer to the Entropy input context
//    pDrbgCtx                     Pointer to the Hash DRBG state
//
// NIST.SP.800-90Ar1 Section 9.3.1 "The Generate Function"
*/

IPPFUN(IppStatus,
       ippsHashDRBG_Gen,
       (Ipp32u * pRand,
        int nBits,
        const int requestedSecurityStrength,
        const int predictionResistanceRequest,
        const Ipp8u* addlInput,
        const int addlInputBitsLen,
        IppsHashDRBG_EntropyInputCtx* pEntrInputCtx,
        IppsHashDRBGState* pDrbgCtx))
{
    IPP_BAD_PTR1_RET(pEntrInputCtx);
    IPP_BAD_PTR1_RET(pDrbgCtx);
    IPP_BAD_PTR1_RET(pRand);

    IPP_BADARG_RET(!HASH_DRBG_ENTR_INPUT_VALID_ID(pEntrInputCtx), ippStsContextMatchErr);
    IPP_BADARG_RET(!HASH_DRBG_VALID_ID(pDrbgCtx), ippStsContextMatchErr);

    IPP_BADARG_RET(requestedSecurityStrength > (int)HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx),
                   ippStsBadArgErr);

    IPP_BADARG_RET(predictionResistanceRequest && !HASH_DRBG_PRED_RESISTANCE_FLAG(pDrbgCtx),
                   ippStsBadArgErr);

    /* test sizes */
    IPP_BADARG_RET((nBits < 1) || (nBits > MAX_BITS_NUMBER_PER_REQUEST), ippStsBadArgErr);
    // The (addlInputBitsLen < 0) check catches a case if addlInputBitsLen > max_personalization_string_length
    IPP_BADARG_RET(addlInputBitsLen < 0, ippStsOutOfRangeErr);
    IPP_BADARG_RET(((NULL == addlInput) && (addlInputBitsLen > 0)) ||
                       ((NULL != addlInput) && (addlInputBitsLen == 0)),
                   ippStsBadArgErr);

    {
        cpSize randLen32 = BITS2WORD32_SIZE(nBits);
        Ipp32u rnd32Mask = MAKEMASK32(nBits);

        IppStatus sts = ippStsNoErr;

        sts = cpHashDRBG_Gen(pRand,
                             randLen32,
                             predictionResistanceRequest,
                             addlInput,
                             addlInputBitsLen,
                             pEntrInputCtx,
                             pDrbgCtx);

        pRand[randLen32 - 1] &= rnd32Mask;

        /* zeroize Hash DRBG hashState */
        PurgeBlock((void*)pDrbgCtx->hashState, HASH_DRBG_HASH_STATE_SIZE(pDrbgCtx));

        if (ippStsNoErr != sts) {
            /* zeroize pRand */
            PurgeBlock((void*)pRand, BITS2WORD8_SIZE(nBits));
            /* zeroize V and C */
            PurgeBlock((void*)pDrbgCtx->V, BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx)));
            PurgeBlock((void*)pDrbgCtx->C, BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN(pDrbgCtx)));
        }

        return sts;
    }
}
