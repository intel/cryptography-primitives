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
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"

/*
//    Name: ippsHashDRBG_GetSize
//
// Purpose: Returns the Hash DRBG context size
//
// Returns:                   Reason:
//    ippStsNullPtrErr           pSize == NULL
//    ippStsNotSupportedModeErr  Hash algorithm isn't supported
//    ippStsErr                  ippsHashGetSize_rmf returned an error
//    ippStsNoErr                No error
//
// Parameters:
//    pSize             Pointer to the size of the Hash DRBG state
//    pHashMethod       Pointer to the provided hash method (may be NULL)
*/

IPPFUN(IppStatus, ippsHashDRBG_GetSize, (int* pSize, const IppsHashMethod* pHashMethod))
{
    IPP_BAD_PTR1_RET(pSize);

    int seedBytesLen;

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
        seedBytesLen     = HASH_DRBG_MIN_SEED_BYTES_LEN;
        securityStrength = HASH_DRBG_MAX_BITS_SEC_STRENGTH;
        break;
    case ippHashAlg_SHA384:
        IPPCP_FALLTHROUGH;
    case ippHashAlg_SHA512:
        seedBytesLen     = HASH_DRBG_MAX_SEED_BYTES_LEN;
        securityStrength = HASH_DRBG_MAX_BITS_SEC_STRENGTH;
        break;
    default:
        return ippStsNotSupportedModeErr;
    }

    IppStatus sts = ippStsNoErr;

    int hashStateSize = 0;
    sts               = ippsHashGetSize_rmf(&hashStateSize);
    if (ippStsNoErr != sts) {
        return sts;
    }

    /* - (2 * (seedBytesLen + 1)) - add 1 byte to seedBytesLen to store zero value at the beginning of the V and tempBuf arrays
       - seedBytesLen             - size of C
       - sec.strength+(1/2)*sec.strength - size of entropyInput array (contains entropy_input and nonce) */

    *pSize = (Ipp32s)sizeof(IppsHashDRBGState) + (2 * (seedBytesLen + 1)) + seedBytesLen +
             hashStateSize + pHashMethod->hashLen + BITS2WORD8_SIZE(securityStrength) +
             (BITS2WORD8_SIZE(securityStrength) / 2);

    return sts;
}
