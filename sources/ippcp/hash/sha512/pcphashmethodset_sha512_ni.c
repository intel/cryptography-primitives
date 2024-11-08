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
//     SHA512 message digest
//
//  Contents:
//        ippsHashMethodSet_SHA512_NI()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"
#include "hash/sha512/pcpsha512stuff.h"

/*F*
//    Name: ippsHashMethodSet_SHA512_NI
//
// Purpose: Setup SHA512 method
// (using the Intel® SHA512 instruction set).
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMethod == NULL
//    ippStsNotSupportedModeErr  mode disabled by configuration
//    ippStsNoErr                no errors
//
*F*/

IPPFUN( IppStatus, ippsHashMethodSet_SHA512_NI, (IppsHashMethod* pMethod) )
{
   IPP_BAD_PTR1_RET(pMethod);

#if (_SHA512_ENABLING_==_FEATURE_TICKTOCK_ || _SHA512_ENABLING_==_FEATURE_ON_)
   pMethod->hashAlgId     = ippHashAlg_SHA512;
   pMethod->hashLen       = IPP_SHA512_DIGEST_BITSIZE/8;
   pMethod->msgBlkSize    = MBS_SHA512;
   pMethod->msgLenRepSize = MLR_SHA512;
   pMethod->hashInit      = sha512_hashInit;
   pMethod->hashUpdate    = sha512_hashUpdate_ni;
   pMethod->hashOctStr    = sha512_hashOctString;
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
