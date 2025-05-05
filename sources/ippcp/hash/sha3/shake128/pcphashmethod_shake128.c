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
//    Name: ippsHashMethod_SHAKE128
//
// Purpose: Return SHAKE128 method.
//
// Returns:                            Reason:
//    NULL                                digestBitsize is not positive multiple of 8 integer
//    Pointer to SHAKE128 hash-method     no errors
//
*/

IPPFUN( const IppsHashMethod*, ippsHashMethod_SHAKE128, (int digestBitsize) )
{
   IPP_BADARG_RET(digestBitsize <= 0, NULL);
   /* test if digestBitsize is not byte aligned */
   IPP_BADARG_RET(digestBitsize % 8, NULL);

   static IppsHashMethod method = {
      ippHashAlg_SHAKE128,
      0,
      MBS_SHAKE128,
      0,
      IPP_SHA3_STATE_BYTESIZE,
      NULL,
      NULL,
      NULL,
      NULL
   };

   // don't merge `method` initialization with function pointers assignment
   // to prevent relocations (indirect calls) to be generated in the binary
   method.hashLen    = digestBitsize / 8; 
   method.hashInit   = sha3_hashInit;
   method.hashUpdate = shake128_hashUpdate;
   method.hashOctStr = sha3_hashOctString;
   method.msgLenRep  = NULL;

   return &method;
}
