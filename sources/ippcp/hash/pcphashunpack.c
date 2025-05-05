/*************************************************************************
* Copyright (C) 2014 Intel Corporation
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
//     Security Hash Standard
//     General Functionality
// 
//  Contents:
//        ippsHashUnpack()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "pcptool.h"

/*F*
//    Name: ippsHashUnpack
//
// Purpose: Unpack buffer content into the initialized context.
//
// Returns:                Reason:
//    ippStsNullPtrErr           pState == NULL
//                               pBuffer == NULL
//
//    ippStsNotSupportedModeErr  method from the SHA3 family
//
//    ippStsNoErr                no errors
//
// Parameters:
//    pBuffer     pointer to the source buffer
//    pState      pointer hash state
//
*F*/
IPPFUN(IppStatus, ippsHashUnpack,(const Ipp8u* pBuffer, IppsHashState* pState))
{
   /* test pointers */
   IPP_BAD_PTR2_RET(pState, pBuffer);
   /* check if the algorithm is from the sha3 family (SHA3 is not supported in non-rmf methods)*/
   IPP_BADARG_RET(cpIsSHA3AlgID(HASH_ALG_ID(pState)), ippStsNotSupportedModeErr);

   CopyBlock(pBuffer, pState, sizeof(IppsHashState));
   HASH_SET_ID(pState, idCtxHash);
   return ippStsNoErr;
}
