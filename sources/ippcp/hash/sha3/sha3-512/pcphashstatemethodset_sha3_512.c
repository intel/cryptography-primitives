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
#include "hash/sha3/sha3-512/pcpsha3_512_stuff.h"

/*
//    Name: ippsHashStateMethodSet_SHA3_512
//
// Purpose: Setup SHA3_512 method inside the hash state.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMethod == NULL or pState == NULL
//    ippStsNoErr             no errors
//
*/
/* clang-format off */
IPPFUN(IppStatus, ippsHashStateMethodSet_SHA3_512, (IppsHashState_rmf* pState,
                                                    IppsHashMethod* pMethod))
/* clang-format on */
{
    /* test pointers */
    IPP_BAD_PTR2_RET(pState, pMethod);

    HASH_METHOD(pState) = pMethod;

    pMethod->hashAlgId     = ippHashAlg_SHA3_512;
    pMethod->hashLen       = IPP_SHA3_512_DIGEST_BITSIZE / 8;
    pMethod->msgBlkSize    = MBS_SHA3_512;
    pMethod->msgLenRepSize = 0;
    pMethod->stateLen      = IPP_SHA3_STATE_BYTESIZE;
    pMethod->hashInit      = cp_sha3_hashInit;
    pMethod->hashUpdate    = cp_sha3_512_hashUpdate;
    pMethod->hashOctStr    = cp_sha3_hashOctString;
    pMethod->msgLenRep     = NULL;

    return ippStsNoErr;
}
