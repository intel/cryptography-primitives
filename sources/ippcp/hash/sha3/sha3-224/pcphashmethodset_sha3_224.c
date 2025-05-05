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
#include "hash/sha3/sha3-224/pcpsha3_224_stuff.h"
#include "hash/sha3/sha3_stuff.h"

/*
//    Name: ippsHashMethodSet_SHA3_224
//
// Purpose: Setup SHA3_224 method.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMethod == NULL
//    ippStsNoErr             no errors
//
*/
IPPFUN( IppStatus, ippsHashMethodSet_SHA3_224, (IppsHashMethod* pMethod) )
{
   /* test pointers */
   IPP_BAD_PTR1_RET(pMethod);

   pMethod->hashAlgId     = ippHashAlg_SHA3_224;
   pMethod->hashLen       = IPP_SHA3_224_DIGEST_BITSIZE/8,
   pMethod->msgBlkSize    = MBS_SHA3_224;
   pMethod->msgLenRepSize = 0;
   pMethod->stateLen      = IPP_SHA3_STATE_BYTESIZE;
   pMethod->hashInit      = sha3_hashInit;
   pMethod->hashUpdate    = sha3_224_hashUpdate;
   pMethod->hashOctStr    = sha3_hashOctString;
   pMethod->msgLenRep     = NULL;

   return ippStsNoErr;
}
