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
//    Name: ippsHashDRBG_Init
//
// Purpose: Initializes Hash DRBG state
//
// Returns:                    Reason:
//    ippStsNullPtrErr           pDrbgCtx == NULL
//    ippStsNotSupportedModeErr  Hash algorithm isn't supported
//    ippStsErr                  ippsHashDRBG_GetSize returned error
//                               ippsHashGetSize_rmf returned error
//    ippStsNoErr                No errors
//
// Parameters:
//    pHashMethod       Pointer to the provided hash method
//    pDrbgCtx          Pointer to the Hash DRBG state
//
*/

IPPFUN(IppStatus,
       ippsHashDRBG_Init,
       (const IppsHashMethod* pHashMethod, IppsHashDRBGState* pDrbgCtx))
{
    IPP_BAD_PTR1_RET(pDrbgCtx);

    {
        IppStatus sts = ippStsNoErr;

        /* cleanup context */
        int size;
        sts = ippsHashDRBG_GetSize(&size, pHashMethod);
        if (ippStsNoErr != sts) {
            return sts;
        }
        PurgeBlock((void*)pDrbgCtx, size);

        // If the hash method is not specified, set SHA-256 by default
        pDrbgCtx->pHashMethod = (pHashMethod == NULL) ? (IppsHashMethod*)ippsHashMethod_SHA256_TT()
                                                      : (IppsHashMethod*)pHashMethod;

        IppHashAlgId algID = pDrbgCtx->pHashMethod->hashAlgId;

        /* Based on SP 800-57 Part 1 Rev. 5 Table 3, maximum security strength for SHA-256,
           SHA-512/256, SHA-384, SHA-512 hash functions equals to or more than 256 bits.
           Based on NIST.SP.800-90Ar1 Table 1, for maximum designed sec.strength equaling to 256 bits
           possible instantiated sec.strengths can be 128, 192 and 256 bits.
           Min. value for requestedSecurityStrength equals to 128 bits */

        /* Note: Set securityStrength to maximum designed for particular hash function sec.strength */

        switch ((int)algID) {
        case ippHashAlg_SHA256:
            IPPCP_FALLTHROUGH;
        case ippHashAlg_SHA512_256:
            HASH_DRBG_SEEDBITS_LEN(pDrbgCtx)      = HASH_DRBG_MIN_SEED_BITS_LEN;
            HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx) = HASH_DRBG_MAX_BITS_SEC_STRENGTH;
            break;
        case ippHashAlg_SHA384:
            IPPCP_FALLTHROUGH;
        case ippHashAlg_SHA512:
            HASH_DRBG_SEEDBITS_LEN(pDrbgCtx)      = HASH_DRBG_MAX_SEED_BITS_LEN;
            HASH_DRBG_SECURITY_STRENGTH(pDrbgCtx) = HASH_DRBG_MAX_BITS_SEC_STRENGTH;
            break;
        default:
            return ippStsNotSupportedModeErr;
        }

        int hashStateSize = 0;
        sts               = ippsHashGetSize_rmf(&hashStateSize);
        if (ippStsNoErr != sts) {
            return sts;
        }
        HASH_DRBG_HASH_STATE_SIZE(pDrbgCtx) = hashStateSize;

        HASH_DRBG_SET_ID(pDrbgCtx);

        Ipp8u* pTempCtx = (Ipp8u*)pDrbgCtx;
        pTempCtx += sizeof(IppsHashDRBGState);
        pDrbgCtx->V = (Ipp8u*)pTempCtx;
        pTempCtx += BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx));
        pDrbgCtx->C = (Ipp8u*)pTempCtx;
        pTempCtx += BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN(pDrbgCtx));
        pDrbgCtx->tempBuf = (Ipp8u*)pTempCtx;
        pTempCtx += BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN_EXT(pDrbgCtx));

        pDrbgCtx->hashState = (IppsHashState_rmf*)pTempCtx;
        pTempCtx += hashStateSize;

        pDrbgCtx->hashOutputBuf = (Ipp8u*)pTempCtx;
        pTempCtx += pDrbgCtx->pHashMethod->hashLen;
    }

    return ippStsNoErr;
}
