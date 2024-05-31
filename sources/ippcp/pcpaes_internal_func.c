/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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
//        * Initialization functions for internal methods and pointers inside AES cipher context
//
*/

#include "pcpaes_internal_func.h"
#include "owncp.h"
#include "pcpaesm.h"
#include "pcptool.h"

/*
 * This function set up pointers to encryption and decryption key schedules,
 * dispatches to the right internal methods and sets pointers to them inside the AES state.
 */
IPP_OWN_DEFN(void, cpAes_setup_ptrs_and_methods, (IppsAESSpec * pCtx))
{
   int nExpKeys = rij128nKeys[rij_index(RIJ_NK(pCtx))];

   RIJ_EKEYS(pCtx) = (Ipp8u *)(IPP_ALIGNED_PTR(RIJ_KEYS_BUFFER(pCtx), AES_ALIGNMENT));
   RIJ_DKEYS(pCtx) = (Ipp8u *)((Ipp32u *)RIJ_EKEYS(pCtx) + nExpKeys);

#if (_AES_NI_ENABLING_ == _FEATURE_ON_)
   RIJ_AESNI(pCtx)   = AES_NI_ENABLED;
   RIJ_ENCODER(pCtx) = Encrypt_RIJ128_AES_NI; /* AES_NI based encoder */
   RIJ_DECODER(pCtx) = Decrypt_RIJ128_AES_NI; /* AES_NI based decoder */
#else
#if (_AES_NI_ENABLING_ == _FEATURE_TICKTOCK_)
   if (IsFeatureEnabled(ippCPUID_AES) || IsFeatureEnabled(ippCPUID_AVX2VAES)) {
      RIJ_AESNI(pCtx)   = AES_NI_ENABLED;
      RIJ_ENCODER(pCtx) = Encrypt_RIJ128_AES_NI; /* AES_NI based encoder */
      RIJ_DECODER(pCtx) = Decrypt_RIJ128_AES_NI; /* AES_NI based decoder */
   } else
#endif
   {
#if (_ALG_AES_SAFE_ == _ALG_AES_SAFE_COMPOSITE_GF_)
      {
         RIJ_ENCODER(pCtx) = SafeEncrypt_RIJ128; /* safe encoder (composite GF) */
         RIJ_DECODER(pCtx) = SafeDecrypt_RIJ128; /* safe decoder (composite GF)*/
      }
#else
      {
         RIJ_ENCODER(pCtx) = Safe2Encrypt_RIJ128; /* safe encoder (compact Sbox)) */
         RIJ_DECODER(pCtx) = Safe2Decrypt_RIJ128; /* safe decoder (compact Sbox)) */
      }
#endif
   }
#endif
}
