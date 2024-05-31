/*************************************************************************
* Copyright (C) 2013 Intel Corporation
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
//     AES-GCM
//
//  Contents:
//        ippsAES_GCMInit()
//
*/

#include "aes_gcm_avx512.h"
#include "owndefs.h"
#include "owncp.h"
#include "pcpaesm.h"
#include "pcptool.h"
#include "pcpaes_gcm_internal_func.h"

#if (_ALG_AES_SAFE_==_ALG_AES_SAFE_COMPACT_SBOX_)
#  include "pcprijtables.h"
#endif

#if(_IPP32E>=_IPP32E_K0)
#include "pcpaesauthgcm_avx512.h"
#include "aes_keyexp.h"
#else
#include "pcpaesauthgcm.h"
#endif /* #if(_IPP32E>=_IPP32E_K0) */

/*F*
//    Name: ippsAES_GCMInit
//
// Purpose: Init AES_GCM context for future usage.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pState == NULL
//    ippStsMemAllocErr       size of buffer is not match for operation
//    ippStsLengthErr         keyLen != 16 &&
//                                   != 24 &&
//                                   != 32
//    ippStsNoErr             no errors
//
// Parameters:
//    pKey        pointer to the secret key
//    keyLen      length of secret key
//    pState      pointer to the AES-GCM context
//    ctxSize     available size (in bytes) of buffer above
//
*F*/
IPPFUN(IppStatus, ippsAES_GCMInit,(const Ipp8u* pKey, int keyLen, IppsAES_GCMState* pState, int ctxSize))
{
   /* test pCtx pointer */
   IPP_BAD_PTR1_RET(pState);

   /* test available size of context buffer */
   IPP_BADARG_RET(ctxSize<cpSizeofCtx_AESGCM(), ippStsMemAllocErr);

   /* use aligned context */
   pState = (IppsAES_GCMState*)( IPP_ALIGNED_PTR(pState, AESGCM_ALIGNMENT) );

   /* set and clear GCM context */
   AESGCM_SET_ID(pState);
   ippsAES_GCMReset(pState);

   /* make sure in legal keyLen */
   IPP_BADARG_RET(keyLen!=16 && keyLen!=24 && keyLen!=32, ippStsLengthErr);

   /* Setup pointers to internal data and methods */
   cpAesGCM_setup_ptrs_and_methods(pState, (Ipp64u)keyLen);

#if(_IPP32E>=_IPP32E_K0)
   AES_GCM_KEY_LEN(pState) = (Ipp64u)keyLen;

   Ipp8u zeroKey[32] = {0};
   const Ipp8u* pActualKey = pKey? pKey : zeroKey;

#if (_AES_PROB_NOISE == _FEATURE_ON_)
      /* Reset AES noise parameters */
      cpAESNoiseParams *params = (cpAESNoiseParams *)&AESGCM_NOISE_PARAMS(pState);

      AES_NOISE_RAND(params)       = 0;
      AES_NOISE_LEVEL(params)      = 0;
#endif
   if (IsFeatureEnabled(ippCPUID_AVX512VAES) && IsFeatureEnabled(ippCPUID_AVX512VCLMUL)) {

      switch AES_GCM_KEY_LEN(pState) {
         case 16:
            aes_keyexp_128_enc(pActualKey, &AES_GCM_KEY_DATA(pState));
            aes_gcm_precomp_128_vaes_avx512(&AES_GCM_KEY_DATA(pState));
            break;
         case 24:
            aes_keyexp_192_enc(pActualKey, &AES_GCM_KEY_DATA(pState));
            aes_gcm_precomp_192_vaes_avx512(&AES_GCM_KEY_DATA(pState));
            break;
         case 32:
            aes_keyexp_256_enc(pActualKey, &AES_GCM_KEY_DATA(pState));
            aes_gcm_precomp_256_vaes_avx512(&AES_GCM_KEY_DATA(pState));
            break;
      }
   } else {

      switch AES_GCM_KEY_LEN(pState) {
         case 16:
            aes_keyexp_128_enc(pActualKey, &AES_GCM_KEY_DATA(pState));
            aes_gcm_precomp_128_avx512(&AES_GCM_KEY_DATA(pState));
            break;
         case 24:
            aes_keyexp_192_enc(pActualKey, &AES_GCM_KEY_DATA(pState));
            aes_gcm_precomp_192_avx512(&AES_GCM_KEY_DATA(pState));
            break;
         case 32:
            aes_keyexp_256_enc(pActualKey, &AES_GCM_KEY_DATA(pState));
            aes_gcm_precomp_256_avx512(&AES_GCM_KEY_DATA(pState));
            break;
      }
   }

#else

   /* init cipher */
   {
      IppStatus sts = ippsAESInit(pKey, keyLen, AESGCM_CIPHER(pState), cpSizeofCtx_AES());
      if(ippStsNoErr!=sts)
         return sts;
   }

   /* precomputations (for constant multiplier(s)) */
   {
      IppsAESSpec* pAES = AESGCM_CIPHER(pState);
      RijnCipher encoder = RIJ_ENCODER(pAES);

      /* multiplier c = Enc({0}) */
      PadBlock(0, AESGCM_HKEY(pState), BLOCK_SIZE);
      //encoder((Ipp32u*)AESGCM_HKEY(pState), (Ipp32u*)AESGCM_HKEY(pState), RIJ_NR(pAES), RIJ_EKEYS(pAES), (const Ipp32u (*)[256])RIJ_ENC_SBOX(pAES));
      #if (_ALG_AES_SAFE_==_ALG_AES_SAFE_COMPACT_SBOX_)
      encoder(AESGCM_HKEY(pState), AESGCM_HKEY(pState), RIJ_NR(pAES), RIJ_EKEYS(pAES), RijEncSbox/*NULL*/);
      #else
      encoder(AESGCM_HKEY(pState), AESGCM_HKEY(pState), RIJ_NR(pAES), RIJ_EKEYS(pAES), NULL);
      #endif
   }

   #if (_IPP >=_IPP_H9) || (_IPP32E>=_IPP32E_L9)
      if (IsFeatureEnabled(ippCPUID_AVX2VAES|ippCPUID_AVX2VCLMUL)) {
         AesGcmPrecompute_avx2_vaes(AESGCM_CPWR(pState), AESGCM_HKEY(pState));
      }
      else
   #endif /* #if (_IPP==_IPP_H9) || (_IPP32E==_IPP32E_L9) */

   #if (_IPP>=_IPP_P8) || (_IPP32E>=_IPP32E_Y8)
         if(IsFeatureEnabled(ippCPUID_AES|ippCPUID_CLMUL)) {
            /* pre-compute reflect(hkey) and hKey<<1, (hKey<<1)^2 and (hKey<<1)^4 powers of hKey */
            AesGcmPrecompute_avx(AESGCM_CPWR(pState), AESGCM_HKEY(pState));
         }
         else
   #endif /* #if (_IPP>=_IPP_P8) || (_IPP32E>=_IPP32E_Y8) */
         AesGcmPrecompute_table2K(AES_GCM_MTBL(pState), AESGCM_HKEY(pState));

#endif /* #if(_IPP32E>=_IPP32E_K0) */


   return ippStsNoErr;
}
