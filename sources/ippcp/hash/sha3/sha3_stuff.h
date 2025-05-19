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
//     SHA3 Family General Functionality
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcptool.h"
#include "hash/pcphash.h"

#if !defined(_SHA3_STUFF_H)
#define _SHA3_STUFF_H

#define KECCAK_ROUNDS 24

#define cp_keccak_kernel OWNAPI(cp_keccak_kernel)
IPP_OWN_DECL(void, cp_keccak_kernel, (Ipp64u state[25]))

#define cpUpdateSHA3 OWNAPI(cpUpdateSHA3)
IPP_OWN_DECL(void, cpUpdateSHA3, (void* uniHash, const Ipp8u* mblk, int mlen, const void* pParam))

#define cp_sha3_hashInit OWNAPI(cp_sha3_hashInit)
IPP_OWN_DECL(void, cp_sha3_hashInit, (void* pHash))

#define cp_sha3_hashOctString OWNAPI(cp_sha3_hashOctString)
IPP_OWN_DECL(void, cp_sha3_hashOctString, (Ipp8u * pMD, void* pHashVal, const int hashSize))

#endif /* #if !defined(_SHA3_STUFF_H) */
