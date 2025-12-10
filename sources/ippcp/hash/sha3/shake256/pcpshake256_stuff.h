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
#include "hash/sha3/sha3_stuff.h"

#if !defined(_PCP_SHAKE256_STUFF_H)
#define _PCP_SHAKE256_STUFF_H

IPP_OWN_DEFN(static void, cp_shake256_hashUpdate, (void* pHash, const Ipp8u* pMsg, int msgLen))
{
    int block_size = MBS_SHAKE256;
#if (_IPP32E >= _IPP32E_K0)
    IPP_UNREFERENCED_PARAMETER(block_size);
    cp_SHA3_SHAKE256_Absorb(&pHash, pMsg, (Ipp64u)msgLen);
#else
    cpUpdateSHA3(pHash, pMsg, msgLen, &block_size);
#endif
}

#endif /* _PCP_SHAKE256_STUFF_H */
