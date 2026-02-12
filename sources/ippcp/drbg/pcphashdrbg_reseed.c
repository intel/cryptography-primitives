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
#include "pcptool.h"
#include "drbg/pcphashdrbg.h"
#include "drbg/pcphashdrbg_entropy_input.h"

/*
//    Name: ippsHashDRBG_Reseed
//
// The Hash_DRBG Reseed Process as listed in SP800-90Ar1 10.1.1.4.
// Purpose: Inserts additional entropy into the generation of pseudorandom bits
//          by refreshing V and C arrays containing seeds.
//          Reseeding may be:
//             - explicitly requested by a consuming application;
//             - performed when prediction resistance is requested
//               (invoked in ippsHashDRBG_Gen() before generating)
//             - reseedCounter is more than MAX_RESEED_INTERVAL
//
// Returns:                     Reason:
//    ippStsNullPtrErr           pDrbgCtx == NULL
//                               Obtained from cpHashDRBG_GetEntropyInput entropyInput is NULL
//    ippStsOutOfRangeErr        addlInputBitsLen < 0 (if len exceeds MAX additional input length)
//                               cpHashDRBG_GetEntropyInput returns this error if entrInputBitsLen is out of range
//                               (if the entrInputBitsLen is less than sec.strength or is more than
//                               the maximum number of bits that can fit in the entropyInput buffer)
//    ippStsContextMatchErr      If the Hash DRBG identifier doesn't match
//                               If the Entropy input context identifier doesn't match
//    ippStsBadArgErr            Prediction resistance is requested but predictionResistanceFlag hasn't been set
//                               addlInput == NULL and addlInputBitsLen > 0 or
//                               addlInput != NULL, but addlInputBitsLen == 0
//    ippStsNotSupportedModeErr  cpHashDRBG_GetEntropyInput returns this error if the CPU doesn't support
//                               either RDSEED or RDRAND
//    ippStsHashOperationErr     cpHashDRBG_df returns this error if sth goes wrong when hashing
//    ippStsNoErr                No errors
//
// Parameters:
//    predictionResistanceRequest Indicates whether or not prediction resistance is to be provided
//                                during the request (i.e., whether or not fresh entropy bits are required)
//    addlInput                   Pointer to the array containing additional input (optional)
//    addlInputBitsLen            Length of the addlInput string in bits (may be zero)
//    pEntrInputCtx               Pointer to the Entropy input context
//    pDrbgCtx                    Pointer to the Hash DRBG state
//
// NIST.SP.800-90Ar1 Section 9.2 "Reseeding a DRBG Instantiation" and
// Section 10.1.1.3 "Reseeding a Hash_DRBG Instantiation"
//
// The algorithm is:
//      seed_material = 0x01 || V || entropy_input || additional_input
//      seed = Hash_df (seed_material, seedlen)
//      V = seed
//      C = Hash_df ((0x00 || V), seedlen)
//      reseed_counter = 1
//      Return (V, C, and reseed_counter)
*/

IPPFUN(IppStatus,
       ippsHashDRBG_Reseed,
       (const int predictionResistanceRequest,
        const Ipp8u* addlInput,
        const int addlInputBitsLen,
        IppsHashDRBG_EntropyInputCtx* pEntrInputCtx,
        IppsHashDRBGState* pDrbgCtx))
{
    IPP_BAD_PTR1_RET(pEntrInputCtx);
    IPP_BAD_PTR1_RET(pDrbgCtx);

    IPP_BADARG_RET(!HASH_DRBG_ENTR_INPUT_VALID_ID(pEntrInputCtx), ippStsContextMatchErr);
    IPP_BADARG_RET(!HASH_DRBG_VALID_ID(pDrbgCtx), ippStsContextMatchErr);

    IPP_BADARG_RET(predictionResistanceRequest && !HASH_DRBG_PRED_RESISTANCE_FLAG(pDrbgCtx),
                   ippStsBadArgErr);

    // The (addlInputBitsLen < 0) check catches a case if addlInputBitsLen > max_personalization_string_length
    IPP_BADARG_RET(addlInputBitsLen < 0, ippStsOutOfRangeErr);
    IPP_BADARG_RET(((NULL == addlInput) && (addlInputBitsLen > 0)) ||
                       ((NULL != addlInput) && (addlInputBitsLen == 0)),
                   ippStsBadArgErr);

    {
        IppStatus sts = ippStsNoErr;

        int entrInputBitsLen;
        sts = cpHashDRBG_GetEntropyInput((int)HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx),
                                         predictionResistanceRequest,
                                         &entrInputBitsLen,
                                         pEntrInputCtx);
        if (ippStsNoErr != sts) {
            /* zeroize pEntrInputCtx->entropyInput */
            PurgeBlock((void*)pEntrInputCtx->entropyInput,
                       BITS2WORD8_SIZE(pEntrInputCtx->entrInputBufBitsLen));
            return sts;
        }

        Ipp8u* entrInputTmp = pEntrInputCtx->entropyInput;

        int seedBytesExtLen = BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx));

        COPY_BNU(pDrbgCtx->tempBuf, pDrbgCtx->V, seedBytesExtLen);

        /* seed_material = 0x01 || V || entropy_input || additional_input */
        /* seed = Hash_df (seed_material, seedlen) && V = seed */
        Ipp8u* pTempBuf = pDrbgCtx->tempBuf;
        pTempBuf[0]     = 1;
        sts             = cpHashDRBG_df(pTempBuf,
                            HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx),
                            entrInputTmp,
                            entrInputBitsLen,
                            addlInput,
                            addlInputBitsLen,
                            pDrbgCtx->V + 1,
                            HASH_DRBG_SEEDBITS_LEN(pDrbgCtx),
                            pDrbgCtx);

        /* zeroize tempBuf and entrInputTmp since these values are no longer needed */
        PurgeBlock((void*)pDrbgCtx->tempBuf, seedBytesExtLen);
        PurgeBlock((void*)entrInputTmp, BITS2WORD8_SIZE(pEntrInputCtx->entrInputBufBitsLen));

        if (ippStsNoErr != sts) {
            return sts;
        }

        /* C = Hash_df ((0x00 || V), seedlen) */
        pDrbgCtx->V[0] = 0;
        sts            = cpHashDRBG_df(pDrbgCtx->V,
                            HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx),
                            NULL,
                            0,
                            NULL,
                            0,
                            pDrbgCtx->C,
                            HASH_DRBG_SEEDBITS_LEN(pDrbgCtx),
                            pDrbgCtx);
        if (ippStsNoErr != sts) {
            /* zeroize pDrbgCtx->V */
            PurgeBlock((void*)pDrbgCtx->V, BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx)));
            return sts;
        }

        /* reseed_counter = 1 */
        HASH_DRBG_RESEED_COUNTER(pDrbgCtx) = 1;

        return sts;
    }
}
