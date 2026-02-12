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
#include "pcpbn.h"
#include "hash/pcphash.h"
#include "drbg/pcphashdrbg.h"
#include "drbg/pcphashdrbg_entropy_input.h"
#include "pcptool.h"

/*
//    Name: ippsHashDRBG_GenBN
//
// Purpose: Generates a pseudorandom positive Big Number of the specified bit length
//
// Returns:                Reason:
//    ippStsNullPtrErr           pRand         == NULL
//                               pDrbgCtx      == NULL
//                               pEntrInputCtx == NULL
//                               cpHashDRBG_Gen returns this error if obtained entropyInput is NULL
//    ippStsContextMatchErr      If the DRBG identifier doesn't match
//                               If Big Number identifier doesn't match
//                               If the Entropy input context identifier doesn't match
//    ippStsBadArgErr            Prediction resistance is requested but predictionResistanceFlag has been set to 0
//                               nBits            < 1
//                               nBits            > Max number of bits per request
//                               nBits            > Big Num max size * BNU_CHUNK_BITS
//                               addlInput        == NULL and addlInputBitsLen > 0 or
//                               addlInput        != NULL, but addlInputBitsLen == 0
//    ippStsOutOfRangeErr        addlInputBitsLen < 0 (if len exceeds MAX additional input length)
//                               cpHashDRBG_Gen returns this error if entrInputBitsLen is out of range
//    ippStsHashOperationErr     cpHashDRBG_Gen returns this error if sth goes wrong when hashing
//    ippStsNotSupportedModeErr  cpHashDRBG_Gen returns this error if the CPU doesn't support RDSEED or RDRAND
//    ippStsNoErr                No errors
//
// Parameters:
//    pRand                        Pointer to the output pseudorandom Big Number
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
       ippsHashDRBG_GenBN,
       (IppsBigNumState * pRand,
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
    IPP_BADARG_RET(!BN_VALID_ID(pRand), ippStsContextMatchErr);

    IPP_BADARG_RET(requestedSecurityStrength > (int)HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx),
                   ippStsBadArgErr);

    IPP_BADARG_RET(predictionResistanceRequest && !HASH_DRBG_PRED_RESISTANCE_FLAG(pDrbgCtx),
                   ippStsBadArgErr);

    /* test sizes */
    IPP_BADARG_RET((nBits < 1) || (nBits > MAX_BITS_NUMBER_PER_REQUEST), ippStsBadArgErr);
    IPP_BADARG_RET(nBits > BN_ROOM(pRand) * BNU_CHUNK_BITS, ippStsBadArgErr);
    // The (addlInputBitsLen < 0) check catches a case if addlInputBitsLen > max_personalization_string_length
    IPP_BADARG_RET(addlInputBitsLen < 0, ippStsOutOfRangeErr);
    IPP_BADARG_RET(((NULL == addlInput) && (addlInputBitsLen > 0)) ||
                       ((NULL != addlInput) && (addlInputBitsLen == 0)),
                   ippStsBadArgErr);

    {
        BNU_CHUNK_T* pRandBN = BN_NUMBER(pRand);
        cpSize rndSize       = BITS_BNU_CHUNK(nBits);
        BNU_CHUNK_T rndMask  = MASK_BNU_CHUNK(nBits);
        cpSize randLen32     = BITS2WORD32_SIZE(nBits);

        IppStatus sts = ippStsNoErr;

        sts = cpHashDRBG_Gen((Ipp32u*)pRandBN,
                             randLen32,
                             predictionResistanceRequest,
                             addlInput,
                             addlInputBitsLen,
                             pEntrInputCtx,
                             pDrbgCtx);

        pRandBN[rndSize - 1] &= rndMask;

        FIX_BNU(pRandBN, rndSize);
        BN_SIZE(pRand) = rndSize;
        BN_SIGN(pRand) = ippBigNumPOS;

        /* zeroize Hash DRBG hashState */
        PurgeBlock((void*)pDrbgCtx->hashState, HASH_DRBG_HASH_STATE_SIZE(pDrbgCtx));

        if (ippStsNoErr != sts) {
            /* zeroize pRandBN */
            PurgeBlock((void*)pRandBN, BITS2WORD8_SIZE(nBits));
            /* zeroize V and C */
            PurgeBlock((void*)pDrbgCtx->V, BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx)));
            PurgeBlock((void*)pDrbgCtx->C, BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN(pDrbgCtx)));
        }

        return sts;
    }
}
