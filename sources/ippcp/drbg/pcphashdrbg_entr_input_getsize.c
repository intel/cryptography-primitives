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
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "drbg/pcphashdrbg.h"
#include "drbg/pcphashdrbg_entropy_input.h"

/*
//    Name: ippsHashDRBG_EntropyInputCtxGetSize
//
// Purpose: Returns the Entropy input context size
//
// Returns:                     Reason:
//    ippStsNullPtrErr           pEntrInputSize == NULL
//    ippStsNotSupportedModeErr  Hash algorithm isn't supported
//    ippStsOutOfRangeErr        entrInputBufBitsLen exceeds max value or is 0
//    ippStsLengthErr            entrInputBufBitsLen is less than (sec.strength + ½ sec.strength)
//    ippStsNoErr                No errors
//
// Parameters:
//    pEntrInputSize        Pointer to the Entropy input context size
//    entrInputBufBitsLen   The length of the buffer containing entropy input
//    pHashMethod           Pointer to the provided hash method (may be NULL)
*/

IPPFUN(IppStatus,
       ippsHashDRBG_EntropyInputCtxGetSize,
       (int* pEntrInputSize, const int entrInputBufBitsLen, const IppsHashMethod* pHashMethod))
{
    IPP_BAD_PTR1_RET(pEntrInputSize);

    {
        /* entrInputBufBitsLen < 1
           1) if the length exceeds max value, an integer overflow occurs
              that results to a change of the sign
           2) entrInputBufBitsLen cannot be zero */
        if (entrInputBufBitsLen < 1) {
            return ippStsOutOfRangeErr;
        }

        // If the hash method is not specified, use SHA-256 by default
        if (pHashMethod == NULL) {
            pHashMethod = ippsHashMethod_SHA256_TT();
        }

        IppHashAlgId algID = pHashMethod->hashAlgId;

        int securityStrength;

        switch ((int)algID) {
        case ippHashAlg_SHA256:
            IPPCP_FALLTHROUGH;
        case ippHashAlg_SHA512_256:
            IPPCP_FALLTHROUGH;
        case ippHashAlg_SHA384:
            IPPCP_FALLTHROUGH;
        case ippHashAlg_SHA512:
            securityStrength = HASH_DRBG_MAX_BITS_SEC_STRENGTH;
            break;
        default:
            return ippStsNotSupportedModeErr;
        }

        // The length of the Entropy input buffer must be equal to or greater than 384 bits
        if (entrInputBufBitsLen < (securityStrength + (securityStrength / 2))) {
            return ippStsLengthErr;
        }

        *pEntrInputSize =
            (int)sizeof(IppsHashDRBG_EntropyInputCtx) + BITS2WORD8_SIZE(entrInputBufBitsLen);
    }

    return ippStsNoErr;
}
