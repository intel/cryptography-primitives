/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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
//     SHA384 message digest
//
//  Contents:
//        ippsHashStateMethodSet_SHA384_NI()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"
#include "hash/sha512/pcpsha512stuff.h"

/*F*
//    Name: ippsHashStateMethodSet_SHA384_NI
//
// Purpose: Setup SHA384 method inside the hash state
// (using the Intel® SHA512 instruction set).
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMethod == NULL or pState == NULL
//    ippStsNotSupportedModeErr  mode disabled by configuration
//    ippStsNoErr                no errors
//
*F*/

IPPFUN( IppStatus, ippsHashStateMethodSet_SHA384_NI, (IppsHashState_rmf* pState, IppsHashMethod* pMethod) )
{
   /* test pointers */
   IPP_BAD_PTR2_RET(pState, pMethod);

   HASH_METHOD(pState) = pMethod;

#if (_SHA512_ENABLING_==_FEATURE_TICKTOCK_ || _SHA512_ENABLING_==_FEATURE_ON_)
   pMethod->hashAlgId     = ippHashAlg_SHA384;
   pMethod->hashLen       = IPP_SHA384_DIGEST_BITSIZE/8;
   pMethod->msgBlkSize    = MBS_SHA512;
   pMethod->msgLenRepSize = MLR_SHA512;
   pMethod->hashInit      = sha512_384_hashInit;
   pMethod->hashUpdate    = sha512_hashUpdate_ni;
   pMethod->hashOctStr    = sha512_384_hashOctString;
   pMethod->msgLenRep     = sha512_msgRep;

   return ippStsNoErr;
#else
   pMethod->hashAlgId     = ippHashAlg_Unknown;
   pMethod->hashLen       = 0;
   pMethod->msgBlkSize    = 0;
   pMethod->msgLenRepSize = 0;
   pMethod->hashInit      = 0;
   pMethod->hashUpdate    = 0;
   pMethod->hashOctStr    = 0;
   pMethod->msgLenRep     = 0;

   return ippStsNotSupportedModeErr;
#endif
}
