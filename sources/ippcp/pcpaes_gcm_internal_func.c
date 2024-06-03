/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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
//        * Initialization functions for internal methods and pointers inside AES-GCM context;
//        * AES-GCM encryption kernels with the conditional noise injections mechanism;
//
*/

#include "pcpaes_gcm_internal_func.h"
#include "aes_gcm_avx512.h"
#include "owncp.h"
#include "pcpaesm.h"
#include "pcptool.h"

#if (_IPP32E >= _IPP32E_K0)
#include "pcpaesauthgcm_avx512.h"
#else
#include "pcpaesauthgcm.h"
#endif /* #if(_IPP32E>=_IPP32E_K0) */

/*
 * This function dispatches to the right internal methods and sets pointers to them inside the AES-GCM state.
 */
IPP_OWN_DEFN(void, cpAesGCM_setup_ptrs_and_methods, (IppsAES_GCMState * pState, Ipp64u keyByteLen))
{
#if (_IPP32E >= _IPP32E_K0)
   if (IsFeatureEnabled(ippCPUID_AVX512VAES) && IsFeatureEnabled(ippCPUID_AVX512VCLMUL)) {
      switch (keyByteLen) {
      case 16:
         AES_GCM_ENCRYPT_UPDATE(pState) = aes_gcm_enc_128_update_vaes_avx512;
         AES_GCM_DECRYPT_UPDATE(pState) = aes_gcm_dec_128_update_vaes_avx512;
         AES_GCM_GET_TAG(pState)        = aes_gcm_gettag_128_vaes_avx512;
         break;
      case 24:
         AES_GCM_ENCRYPT_UPDATE(pState) = aes_gcm_enc_192_update_vaes_avx512;
         AES_GCM_DECRYPT_UPDATE(pState) = aes_gcm_dec_192_update_vaes_avx512;
         AES_GCM_GET_TAG(pState)        = aes_gcm_gettag_192_vaes_avx512;
         break;
      case 32:
         AES_GCM_ENCRYPT_UPDATE(pState) = aes_gcm_enc_256_update_vaes_avx512;
         AES_GCM_DECRYPT_UPDATE(pState) = aes_gcm_dec_256_update_vaes_avx512;
         AES_GCM_GET_TAG(pState)        = aes_gcm_gettag_256_vaes_avx512;
         break;
      }

      AES_GCM_IV_UPDATE(pState)   = aes_gcm_iv_hash_update_vaes512;
      AES_GCM_IV_FINALIZE(pState) = aes_gcm_iv_hash_finalize_vaes512;
      AES_GCM_AAD_UPDATE(pState)  = aes_gcm_aad_hash_update_vaes512;
      AES_GCM_GMUL(pState)        = aes_gcm_gmult_vaes512;
   } else {
      switch (keyByteLen) {
      case 16:
         AES_GCM_ENCRYPT_UPDATE(pState) = aes_gcm_enc_128_update_avx512;
         AES_GCM_DECRYPT_UPDATE(pState) = aes_gcm_dec_128_update_avx512;
         AES_GCM_GET_TAG(pState)        = aes_gcm_gettag_128_avx512;
         break;
      case 24:
         AES_GCM_ENCRYPT_UPDATE(pState) = aes_gcm_enc_192_update_avx512;
         AES_GCM_DECRYPT_UPDATE(pState) = aes_gcm_dec_192_update_avx512;
         AES_GCM_GET_TAG(pState)        = aes_gcm_gettag_192_avx512;
         break;
      case 32:
         AES_GCM_ENCRYPT_UPDATE(pState) = aes_gcm_enc_256_update_avx512;
         AES_GCM_DECRYPT_UPDATE(pState) = aes_gcm_dec_256_update_avx512;
         AES_GCM_GET_TAG(pState)        = aes_gcm_gettag_256_avx512;
         break;
      }

      AES_GCM_IV_UPDATE(pState)   = aes_gcm_iv_hash_update_avx512;
      AES_GCM_IV_FINALIZE(pState) = aes_gcm_iv_hash_finalize_avx512;
      AES_GCM_AAD_UPDATE(pState)  = aes_gcm_aad_hash_update_avx512;
      AES_GCM_GMUL(pState)        = aes_gcm_gmult_avx512;
   }
#else
   IPP_UNREFERENCED_PARAMETER(keyByteLen);

   /* set up:
   // - ghash function
   // - authentication function
   */
   AESGCM_HASH(pState) = AesGcmMulGcm_table2K_ct; // AesGcmMulGcm_table2K;
   AESGCM_AUTH(pState) = AesGcmAuth_table2K_ct;   // AesGcmAuth_table2K;
   AESGCM_ENC(pState)  = wrpAesGcmEnc_table2K;
   AESGCM_DEC(pState)  = wrpAesGcmDec_table2K;

#if (_IPP>=_IPP_P8) || (_IPP32E>=_IPP32E_Y8)
// the dead code that currently is unused
//#if (_IPP32E >= _IPP32E_K0)
//   if (IsFeatureEnabled(ippCPUID_AVX512VAES)) {
//      AESGCM_HASH(pState) = AesGcmMulGcm_vaes;
//      AESGCM_AUTH(pState) = AesGcmAuth_vaes;
//      AESGCM_ENC(pState)  = AesGcmEnc_vaes;
//      AESGCM_DEC(pState)  = AesGcmDec_vaes;
//   } else
//#endif /* #if(_IPP32E>=_IPP32E_K0) */
      if (IsFeatureEnabled(ippCPUID_AES | ippCPUID_CLMUL)) {
         AESGCM_HASH(pState) = AesGcmMulGcm_avx;
         AESGCM_AUTH(pState) = AesGcmAuth_avx;
         AESGCM_ENC(pState)  = wrpAesGcmEnc_avx;
         AESGCM_DEC(pState)  = wrpAesGcmDec_avx;
      }
#if (_IPP==_IPP_H9) || (_IPP32E==_IPP32E_L9)
      if (IsFeatureEnabled(ippCPUID_AVX2VAES | ippCPUID_AVX2VCLMUL)) {
         AESGCM_HASH(pState) = AesGcmMulGcm_avx;
         AESGCM_AUTH(pState) = AesGcmAuth_avx;
         AESGCM_ENC(pState)  =  AesGcmEnc_vaes_avx2;
         AESGCM_DEC(pState)  = AesGcmDec_vaes_avx2;
      }
#endif /* #if(_IPP==_IPP_H9) || (_IPP32E==_IPP32E_L9) */
#endif /* #if(_IPP>=_IPP_P8) || (_IPP32E>=_IPP32E_Y8) */

#endif /* #if(_IPP32E>=_IPP32E_K0) */
}

/*!
 * This function computes AES-GCM encryption kernel with the the conditional noise injections mechanism (Mistletoe3 
 * attack mitigation).
 *
 * Parameters:
 *    \param[in] pSrc      Pointer to plaintext.
 *    \param[in] pDst      Pointer to ciphertext.
 *    \param[in] ptxt_len  Length of the plaintext in bytes.
 *    \param[in] pState    Pointer to the AES-GCM context.
 */
IPP_OWN_DEFN(void, condNoisedGCMEncryption, (const Ipp8u* pSrc, Ipp8u* pDst, int ptxt_len,
                                                      IppsAES_GCMState* pState))
{
/* Identify the encryption method. It's different for different platforms */
#if(_IPP32E>=_IPP32E_K0)
   EncryptUpdate_ encFunc = AES_GCM_ENCRYPT_UPDATE(pState);
#else
   Encrypt_ encFunc = AESGCM_ENC(pState);
#endif

#if (_AES_PROB_NOISE == _FEATURE_ON_)
   /* Mistletoe3 mitigation */
   cpAESNoiseParams *params = (cpAESNoiseParams*)&AESGCM_NOISE_PARAMS(pState);
   if (AES_NOISE_LEVEL(params) > 0) {
      /* Number of bytes allowed for operation without adding noise */
      int chunk_size;
      /* Number of bytes remaining for operation */
      int remaining_size = ptxt_len;

      while (remaining_size > 0) {
         /* How many bytes to encrypt in this operation */
         chunk_size = (remaining_size >= MISTLETOE3_MAX_CHUNK_SIZE) ? 
                      MISTLETOE3_MAX_CHUNK_SIZE : 
                      remaining_size;

      #if(_IPP32E>=_IPP32E_K0)
         encFunc(&AES_GCM_KEY_DATA(pState), &AES_GCM_CONTEXT_DATA(pState), 
                 pDst, pSrc, (Ipp64u)chunk_size);
      #else
         encFunc(pDst, pSrc, chunk_size, pState);
      #endif

         cpAESRandomNoise(NULL,
                  MISTLETOE3_BASE_NOISE_LEVEL + AES_NOISE_LEVEL(params),
                  MISTLETOE3_NOISE_RATE,
                  &AES_NOISE_RAND(params));

         pSrc += chunk_size;
         pDst += chunk_size;
         remaining_size -= chunk_size;
      }
   } else
#endif
   { /* Process without noise injection */
   #if(_IPP32E>=_IPP32E_K0)
      encFunc(&AES_GCM_KEY_DATA(pState), &AES_GCM_CONTEXT_DATA(pState), 
              pDst, pSrc, (Ipp64u)ptxt_len);
   #else
      encFunc(pDst, pSrc, ptxt_len, pState);
   #endif
   }
}


/*!
 * This function computes AES-GCM decryption kernel with the the conditional noise injections mechanism (Mistletoe3 
 * attack mitigation).
 *
 * Parameters:
 *    \param[in] pSrc      Pointer to ciphertext.
 *    \param[in] pDst      Pointer to deciphered text.
 *    \param[in] ctxt_len  Length of the ciphertext in bytes.
 *    \param[in] pState    Pointer to the AES-GCM context.
 */
IPP_OWN_DEFN(void, condNoisedGCMDecryption, (const Ipp8u* pSrc, Ipp8u* pDst, int ctxt_len, 
                                                      IppsAES_GCMState* pState))
{
/* Identify the decryption method. It's different for different platforms */
#if(_IPP32E>=_IPP32E_K0)
   DecryptUpdate_ decFunc = AES_GCM_DECRYPT_UPDATE(pState);
#else
   Decrypt_ decFunc = AESGCM_DEC(pState);
#endif

#if (_AES_PROB_NOISE == _FEATURE_ON_)
   /* Mistletoe3 mitigation */
   cpAESNoiseParams *params = (cpAESNoiseParams*)&AESGCM_NOISE_PARAMS(pState);
   if (AES_NOISE_LEVEL(params) > 0) {
      /* Number of bytes allowed for operation without adding noise */
      int chunk_size;
      /* Number of bytes remaining for operation */
      int remaining_size = ctxt_len;

      while (remaining_size > 0) {
         /* How many bytes to decrypt in this operation */
         chunk_size = (remaining_size >= MISTLETOE3_MAX_CHUNK_SIZE) ?
                       MISTLETOE3_MAX_CHUNK_SIZE : 
                       remaining_size;

      #if(_IPP32E>=_IPP32E_K0)
         decFunc(&AES_GCM_KEY_DATA(pState), &AES_GCM_CONTEXT_DATA(pState), 
                 pDst, pSrc, (Ipp64u)chunk_size);
      #else
         decFunc(pDst, pSrc, chunk_size, pState);
      #endif

         cpAESRandomNoise(NULL,
                  MISTLETOE3_BASE_NOISE_LEVEL + AES_NOISE_LEVEL(params),
                  MISTLETOE3_NOISE_RATE,
                  &AES_NOISE_RAND(params));

         pSrc += chunk_size;
         pDst += chunk_size;
         remaining_size -= chunk_size;
      }
   } else
#endif
   { /* Process without noise injection */
   #if(_IPP32E>=_IPP32E_K0)
      decFunc(&AES_GCM_KEY_DATA(pState), &AES_GCM_CONTEXT_DATA(pState), 
              pDst, pSrc, (Ipp64u)ctxt_len);
   #else
      decFunc(pDst, pSrc, ctxt_len, pState);
   #endif
   }
}
