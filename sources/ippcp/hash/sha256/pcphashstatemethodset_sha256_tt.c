/*************************************************************************
* Copyright (C) 2022 Intel Corporation
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
//     Digesting message according to SHA256
//
//  Contents:
//        ippsHashStateMethodSet_SHA256_TT()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"
#include "hash/sha256/pcpsha256stuff.h"

/*F*
//    Name: ippsHashStateMethodSet_SHA256_TT
//
// Purpose: Setup SHA256 method inside the hash state
//          (using the Intel® Secure Hash Algorithm - New Instructions (Intel® SHA-NI) instructions set
//             if it is available at run time)
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMethod == NULL or pState == NULL
//    ippStsNoErr                no errors
//
*F*/

IPPFUN( IppStatus, ippsHashStateMethodSet_SHA256_TT, (IppsHashState_rmf* pState, IppsHashMethod* pMethod) )
{
   /* test pointers */
   IPP_BAD_PTR2_RET(pState, pMethod);

   HASH_METHOD(pState) = pMethod;

   pMethod->hashAlgId     =  ippHashAlg_SHA256;
   pMethod->hashLen       =  IPP_SHA256_DIGEST_BITSIZE/8;
   pMethod->msgBlkSize    =  MBS_SHA256;
   pMethod->msgLenRepSize =  MLR_SHA256;
   pMethod->hashInit      =  sha256_hashInit;
   pMethod->hashUpdate    =  sha256_hashUpdate;
   pMethod->hashOctStr    =  sha256_hashOctString;
   pMethod->msgLenRep     =  sha256_msgRep;

#if (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_ || _SHA_NI_ENABLING_==_FEATURE_ON_)
   if(IsFeatureEnabled(ippCPUID_SHA))
      pMethod->hashUpdate = sha256_ni_hashUpdate;
#endif

   return ippStsNoErr;
}
