/*******************************************************************************
* Copyright 2013 Intel Corporation
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
//     RSA Functions
// 
//  Contents:
//        ippsRSA_GetPublicKey()
//
*/

#include "owncp.h"
#include "pcpbn.h"
#include "pcpngrsa.h"

/*F*
// Name: ippsRSA_GetPublicKey
//
// Purpose: Extract key component from the key context
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pKey
//
//    ippStsContextMatchErr     !RSA_PUB_KEY_VALID_ID()
//                              !BN_VALID_ID(pModulus)
//                              !BN_VALID_ID(pExp)
//
//    ippStsIncompleteContextErr public key is not set up
//
//    ippStsSizeErr              BN_ROOM(pModulus), BN_ROOM(pExp) is not enough
//
//    ippStsNoErr                no error
//
// Parameters:
//    pModulus    (optional) pointer to the modulus (N)
//    pExp        (optional) pointer to the public exponent (E)
//    pKey        pointer to the key context
*F*/
IPPFUN(IppStatus, ippsRSA_GetPublicKey,(IppsBigNumState* pModulus,
                                        IppsBigNumState* pExp,
                                  const IppsRSAPublicKeyState* pKey))
{
   IPP_BAD_PTR1_RET(pKey);
   IPP_BADARG_RET(!RSA_PUB_KEY_VALID_ID(pKey), ippStsContextMatchErr);

   if(pModulus) {
      IPP_BADARG_RET(!BN_VALID_ID(pModulus), ippStsContextMatchErr);
      IPP_BADARG_RET(!RSA_PUB_KEY_IS_SET(pKey), ippStsIncompleteContextErr);
      IPP_BADARG_RET(BN_ROOM(pModulus)<BITS_BNU_CHUNK(RSA_PUB_KEY_BITSIZE_N(pKey)), ippStsSizeErr);

      BN_Set(MOD_MODULUS(RSA_PUB_KEY_NMONT(pKey)),
             MOD_LEN(RSA_PUB_KEY_NMONT(pKey)),
             pModulus);
   }

   if(pExp) {
      cpSize expLen = BITS_BNU_CHUNK(RSA_PUB_KEY_BITSIZE_E(pKey));
      FIX_BNU(RSA_PUB_KEY_E(pKey), expLen);

      IPP_BADARG_RET(!BN_VALID_ID(pExp), ippStsContextMatchErr);
      IPP_BADARG_RET(!RSA_PUB_KEY_IS_SET(pKey), ippStsIncompleteContextErr);
      IPP_BADARG_RET(BN_ROOM(pExp) < expLen, ippStsSizeErr);

      BN_Set(RSA_PUB_KEY_E(pKey), expLen, pExp);
   }

   return ippStsNoErr;
}
