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

/*
//
//  Purpose:
//     Cryptography Primitive.
//     Digesting message according to SM3
//
//  Contents:
//        ippsHashStateMethodSet_SM3_NI()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"
#include "hash/sm3/pcpsm3stuff.h"

/*F*
//    Name: ippsHashStateMethodSet_SM3_NI
//
// Purpose: Setup SM3 method inside the hash state optimized with SM3 instructions.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMethod == NULL or pState == NULL
//    ippStsNoErr             no errors
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsHashStateMethodSet_SM3_NI, (IppsHashState_rmf* pState,
                                                  IppsHashMethod* pMethod))
/* clang-format on */
{
    /* test pointers */
    IPP_BAD_PTR2_RET(pState, pMethod);

    HASH_METHOD(pState) = pMethod;

#if (_SM3_ENABLING_ == _FEATURE_TICKTOCK_ || _SM3_ENABLING_ == _FEATURE_ON_)
    pMethod->hashAlgId     = ippHashAlg_SM3;
    pMethod->hashLen       = IPP_SM3_DIGEST_BITSIZE / 8;
    pMethod->msgBlkSize    = MBS_SM3;
    pMethod->msgLenRepSize = MLR_SM3;

    pMethod->hashInit   = sm3_hashInit;
    pMethod->hashUpdate = sm3_hashUpdate_ni;
    pMethod->hashOctStr = sm3_hashOctString;
    pMethod->msgLenRep  = sm3_msgRep;

    return ippStsNoErr;
#else
    pMethod->hashAlgId     = ippHashAlg_Unknown;
    pMethod->hashLen       = 0;
    pMethod->msgBlkSize    = 0;
    pMethod->msgLenRepSize = 0;
    pMethod->hashInit      = NULL;
    pMethod->hashUpdate    = NULL;
    pMethod->hashOctStr    = NULL;
    pMethod->msgLenRep     = NULL;

    return ippStsNotSupportedModeErr;
#endif
}
