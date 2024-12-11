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
//        cpInitHash()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_func.h"
#include "pcptool.h"

IPP_OWN_DEFN (int, cpInitHash, (IppsHashState* pCtx, IppHashAlgId algID))
{
   /* setup default processing function */
   HASH_FUNC(pCtx) = cpHashProcFunc[algID];

   /* update default processing function if Intel® Secure Hash Algorithm - New Instructions (Intel® SHA-NI) enabled */
   #if (_IPP>=_IPP_P8) || (_IPP32E>=_IPP32E_Y8)
   if( IsFeatureEnabled(ippCPUID_SHA) ) {

      #if defined(_ENABLE_ALG_SHA1_)
      if(ippHashAlg_SHA1==algID)
         HASH_FUNC(pCtx) = UpdateSHA1ni;
      #endif

      #if defined(_ENABLE_ALG_SHA256_) || defined(_ENABLE_ALG_SHA224_)
      if(ippHashAlg_SHA256==algID || ippHashAlg_SHA224==algID)
         HASH_FUNC(pCtx) = UpdateSHA256ni;
      #endif
   }
   #endif
   #if (_IPP32E >= _IPP32E_L9)
   if (ippHashAlg_SM3==algID && IsFeatureEnabled(ippCPUID_AVX2SM3)) {
      HASH_FUNC(pCtx) = UpdateSM3ni;
   }
   #endif

   /* setup optional agr of processing function */
   HASH_FUNC_PAR(pCtx) = cpHashProcFuncOpt[algID];

   return cpReInitHash(pCtx, algID);
}
