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

/* 
//    Name: ippsHashMethod_SHA3_224
//
// Purpose: Return SHA3_224 method.
//
// Returns:
//          Pointer to SHA3_224 hash-method.
//
*/

IPPFUN(const IppsHashMethod*, ippsHashMethod_SHA3_224, (void))
{
    static IppsHashMethod method = { ippHashAlg_SHA3_224,
                                     IPP_SHA3_224_DIGEST_BITSIZE / 8,
                                     MBS_SHA3_224,
                                     0,
                                     IPP_SHA3_STATE_BYTESIZE,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL };

    // don't merge `method` initialization with function pointers assignment
    // to prevent relocations (indirect calls) to be generated in the binary
    method.hashInit   = sha3_hashInit;
    method.hashUpdate = sha3_224_hashUpdate;
    method.hashOctStr = sha3_hashOctString;
    method.msgLenRep  = NULL;

    return &method;
}
