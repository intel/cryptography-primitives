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
//     SHA512/224 message digest
//
//  Contents:
//        ippsHashMethod_SHA512_224_TT()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"
#include "hash/sha512/pcpsha512stuff.h"

/*F*
//    Name: ippsHashMethod_SHA512_224_TT
//
// Purpose: Return SHA512/224 method
// (using the Intel® SHA512 instruction set if it is available at run time)
//
// Returns:
//          Pointer to SHA512/224 hash-method
//          (using the Intel® SHA512 instruction set if it is available at run time)
//
*F*/

IPPFUN( const IppsHashMethod*, ippsHashMethod_SHA512_224_TT, (void) )
{
   static IppsHashMethod method = {
      ippHashAlg_SHA512_224,
      IPP_SHA224_DIGEST_BITSIZE/8,
      MBS_SHA512,
      MLR_SHA512,
      0,
      0,
      0,
      0
   };

   method.hashInit   = sha512_224_hashInit;
   method.hashUpdate = sha512_hashUpdate;
   method.hashOctStr = sha512_224_hashOctString;
   method.msgLenRep  = sha512_msgRep;

#if (_SHA512_ENABLING_==_FEATURE_TICKTOCK_ || _SHA512_ENABLING_==_FEATURE_ON_)
   if(IsFeatureEnabled(ippCPUID_AVX2SHA512))
      method.hashUpdate = sha512_hashUpdate_ni;
#endif

   return &method;
}
