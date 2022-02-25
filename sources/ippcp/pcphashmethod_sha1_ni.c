/*******************************************************************************
* Copyright 2002 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

/*
//
//  Purpose:
//     Cryptography Primitive.
//     Digesting message according to SHA1
//
//  Contents:
//        ippsHashMethod_SHA1_NI()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcphash.h"
#include "pcphash_rmf.h"
#include "pcptool.h"
#include "pcpsha1stuff.h"

/*F*
//    Name: ippsHashMethod_SHA1_NI
//
// Purpose: Return SHA1 method (using the Intel® Secure Hash Algorithm - New Instructions (Intel® SHA-NI) instruction set).
//
// Returns:
//          Pointer to SHA1 hash-method (using the Intel SHA-NI instruction set).
//
*F*/

IPPFUN( const IppsHashMethod*, ippsHashMethod_SHA1_NI, (void) )
{
   #if (_SHA_NI_ENABLING_==_FEATURE_TICKTOCK_ || _SHA_NI_ENABLING_==_FEATURE_ON_)
   static IppsHashMethod method = {
      ippHashAlg_SHA1,
      IPP_SHA1_DIGEST_BITSIZE/8,
      MBS_SHA1,
      MLR_SHA1,
      0,
      0,
      0,
      0
   };

   method.hashInit   = sha1_hashInit;
   method.hashUpdate = sha1_ni_hashUpdate;
   method.hashOctStr = sha1_hashOctString;
   method.msgLenRep  = sha1_msgRep;

   return &method;
   #else
   return NULL;
   #endif
}
