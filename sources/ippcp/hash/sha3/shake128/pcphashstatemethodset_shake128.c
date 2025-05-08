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

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"
#include "hash/sha3/shake128/pcpshake128_stuff.h"

/*
//    Name: ippsHashStateMethodSet_SHAKE128
//
// Purpose: Setup SHAKE128 method inside the hash state.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMethod == NULL or pState == NULL
//    ippStsOutOfRangeErr     digestBitsize is not positive multiple of 8 integer
//    ippStsNoErr             no errors
//
*/
/* clang-format off */
IPPFUN(IppStatus, ippsHashStateMethodSet_SHAKE128, (IppsHashState_rmf* pState,
                                                    IppsHashMethod* pMethod,
                                                    int digestBitsize))
/* clang-format on */
{
    /* test pointers */
    IPP_BAD_PTR2_RET(pState, pMethod);

    HASH_METHOD(pState) = pMethod;

    if (digestBitsize > 0 && (digestBitsize % 8) == 0) {
        pMethod->hashAlgId     = ippHashAlg_SHAKE128;
        pMethod->hashLen       = digestBitsize / 8;
        pMethod->msgBlkSize    = MBS_SHAKE128;
        pMethod->msgLenRepSize = 0;
        pMethod->stateLen      = IPP_SHA3_STATE_BYTESIZE;
        pMethod->hashInit      = sha3_hashInit;
        pMethod->hashUpdate    = shake128_hashUpdate;
        pMethod->hashOctStr    = sha3_hashOctString;
        pMethod->msgLenRep     = NULL;

        return ippStsNoErr;
    }

    else {
        pMethod->hashAlgId = ippHashAlg_Unknown;
        pMethod->hashLen = 0, pMethod->msgBlkSize = 0;
        pMethod->msgLenRepSize = 0;
        pMethod->stateLen      = 0;
        pMethod->hashInit      = NULL;
        pMethod->hashUpdate    = NULL;
        pMethod->hashOctStr    = NULL;
        pMethod->msgLenRep     = NULL;

        return ippStsOutOfRangeErr;
    }
}
