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
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"

/*
//    Name: ippsHashDRBG_Instantiate
//
// The Hash_DRBG Instantiate Process as listed in SP800-90Ar1 10.1.1.4.
// Purpose: Instantiate Hash DRBG
//
// Returns:                     Reason:
//    ippStsNullPtrErr           pDrbgCtx == NULL
//                               Obtained from cpHashDRBG_GetEntropyInput entropyInput is NULL
//    ippStsContextMatchErr      If the Hash DRBG identifier doesn't match
//                               If the Entropy input context identifier doesn't match
//    ippStsOutOfRangeErr        persStrBitsLen < 0 (if len exceeds MAX pers string length)
//                               cpHashDRBG_GetEntropyInput returns this error if entrInputBitsLen is out of range
//                               (if the entrInputBitsLen is less than (sec.strength + sec.strength/2)
//                               or is more than the maximum number of bits that can fit in the entropyInput buffer)
//    ippStsBadArgErr            RequestedInstSecurityStrength is more than the set sec.strength
//                               persStr == NULL and persStrBitsLen > 0 or
//                               persStr != NULL, but persStrBitsLen == 0
//    ippStsNotSupportedModeErr  cpHashDRBG_GetEntropyInput returns this error if the CPU doesn't support
//                               either RDSEED or RDRAND
//    ippStsHashOperationErr     cpHashDRBG_df returns this error if sth goes wrong when hashing
//    ippStsNoErr                No errors
//
// Parameters:
//    requestedInstSecurityStrength  Requested security strength for the instantiation
//    predictionResistanceFlag       Indicates whether or not prediction resistance may be required
//                                   during one or more requests for pseudorandom bits
//    persStr                        Pointer to the array providing additional bytes for seed material
//                                   (optional but recommended)
//    persStrBitsLen                 Length of the persStr string in bits (may be zero)
//    pEntrInputCtx                  Pointer to the Entropy input context
//    pDrbgCtx                       Pointer to the Hash DRBG state
//
// NIST.SP.800-90Ar1 Section 9.1 "Instantiating a DRBG" and
// Section 10.1.1.2 "Instantiation of Hash_DRBG"
//
// The algorithm is:
//      seed_material = entropy_input || nonce || personalization_string
//      seed = Hash_df (seed_material, seedlen)
//      V = seed
//      C = Hash_df ((0x00 || V), seedlen)
//      reseed_counter = 1
//      Return (V, C, reseed_counter)
//
// NIST.SP.800-90Ar1 Section 9.1 "Instantiating a DRBG".
// Note: if a random value is used in the nonce, the entropy_input and random portion of the nonce
//       could be acquired using a single Get_entropy_input call; in this case, the first parameter
//       of the Get_entropy_input call is adjusted to include the entropy for the nonce (i.e.,
//       the security_strength is increased by at least ½ security_strength, and min-length is
//       increased to accommodate the length of the nonce)
*/

IPPFUN(IppStatus,
       ippsHashDRBG_Instantiate,
       (const int requestedInstSecurityStrength,
        const int predictionResistanceFlag,
        const Ipp8u* persStr,
        const int persStrBitsLen,
        IppsHashDRBG_EntropyInputCtx* pEntrInputCtx,
        IppsHashDRBGState* pDrbgCtx))
{
    IPP_BAD_PTR1_RET(pEntrInputCtx);
    IPP_BAD_PTR1_RET(pDrbgCtx);

    IPP_BADARG_RET(!HASH_DRBG_ENTR_INPUT_VALID_ID(pEntrInputCtx), ippStsContextMatchErr);
    IPP_BADARG_RET(!HASH_DRBG_VALID_ID(pDrbgCtx), ippStsContextMatchErr);

    IPP_BADARG_RET(requestedInstSecurityStrength > (int)HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx),
                   ippStsBadArgErr);

    // The (persStrBitsLen < 0) check catches a case if personalization_string > max_personalization_string_length
    IPP_BADARG_RET(persStrBitsLen < 0, ippStsOutOfRangeErr);
    IPP_BADARG_RET(((NULL == persStr) && (persStrBitsLen > 0)) ||
                       ((NULL != persStr) && (persStrBitsLen == 0)),
                   ippStsBadArgErr);

    {
        // Set predictionResistanceFlag
        HASH_DRBG_PRED_RESISTANCE_FLAG(pDrbgCtx) = predictionResistanceFlag;
        // Change securityStrength if requestedInstSecurityStrength is less than
        // one of the value from the set {128, 198, 256}
        if (requestedInstSecurityStrength <= HASH_DRBG_MIN_SEC_STRENGTH) {
            HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx) = HASH_DRBG_MIN_SEC_STRENGTH;
        } else if (requestedInstSecurityStrength <= HASH_DRBG_SEC_STRENGTH_192) {
            HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx) = HASH_DRBG_SEC_STRENGTH_192;
        }

        IppStatus sts = ippStsNoErr;

        // Based on Note, minEntropyInBits equals to (sec.strength + sec.strength/2)
        int minEntropyInBits = (int)(HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx) +
                                     (HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx) / 2));
        int entrInputBitsLen;
        // Request pred.resistance to be on the safe side and cover either case
        sts = cpHashDRBG_GetEntropyInput(minEntropyInBits,
                                         1, // predictionResistanceRequest
                                         &entrInputBitsLen,
                                         pEntrInputCtx);
        if (ippStsNoErr != sts) {
            /* zeroize pEntrInputCtx->entropyInput */
            PurgeBlock((void*)pEntrInputCtx->entropyInput,
                       BITS2WORD8_SIZE(pEntrInputCtx->entrInputBufBitsLen));
            return sts;
        }

        Ipp8u* entrInputTmp = pEntrInputCtx->entropyInput;

        // V contains 1 additional byte which has to be zero
        pDrbgCtx->V[0] = 0;

        /* Hash_DRBG_Instantiate_algorithm */

        /* seedMaterial = entropy_input || nonce || personalization_string */
        /* seed = Hash_df (seedMaterial, seedlen) && V = seed */
        sts = cpHashDRBG_df(entrInputTmp,
                            entrInputBitsLen,
                            NULL,
                            0,
                            persStr,
                            persStrBitsLen,
                            pDrbgCtx->V + 1,
                            HASH_DRBG_SEEDBITS_LEN(pDrbgCtx),
                            pDrbgCtx);

        /* zeroize entrInputTmp since it's no longer needed */
        PurgeBlock((void*)entrInputTmp, BITS2WORD8_SIZE(pEntrInputCtx->entrInputBufBitsLen));

        if (ippStsNoErr != sts) {
            return sts;
        }

        /* C = Hash_df ((0x00 || V), seedlen) */
        /* Since V already contains zero in the zeroth element we just pass the pointer to V */
        sts = cpHashDRBG_df(pDrbgCtx->V,
                            HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx),
                            NULL,
                            0,
                            NULL,
                            0,
                            pDrbgCtx->C,
                            HASH_DRBG_SEEDBITS_LEN(pDrbgCtx),
                            pDrbgCtx);
        if (ippStsNoErr != sts) {
            /* zeroize V */
            PurgeBlock((void*)pDrbgCtx->V, BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx)));
            return sts;
        }

        /* reseed_counter = 1 */
        HASH_DRBG_RESEED_COUNTER(pDrbgCtx) = 1;

        return sts;
    }
}
