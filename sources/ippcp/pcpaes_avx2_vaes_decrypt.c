/*************************************************************************
* Copyright (C) 2023 Intel Corporation
*
* Licensed under the Apache License,  Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
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
//     AES decryption (GCM mode)
//
*/

#include "pcpaes_avx2_vaes.h"

#if (_IPP==_IPP_H9) || (_IPP32E==_IPP32E_L9)

IPP_OWN_DEFN (void, AesGcmDec_vaes_avx2, (Ipp8u* pDst, const Ipp8u* pSrc, int len, IppsAES_GCMState* pState))
{
   // dispatching to older code path in case of short plain text
   if (len < 256) {
      IppsAESSpec* pAES = AESGCM_CIPHER(pState);
      RijnCipher encoder = RIJ_ENCODER(pAES);
      Ipp8u hkeys_old_order[48];

      // put the hash keys in the correct order (hKey*t, (hKey*t)^2, (hKey*t)^4)
      for (int i = 0; i < 32; i++) {
         *(hkeys_old_order+i) = *(AESGCM_HKEY(pState)+i); // HKEY 0-32
         if (i < 16)
            *(hkeys_old_order+i+32) = *(AESGCM_HKEY(pState)+i+48); // HKEY 32-48
      }

      AesGcmDec_avx(pDst, pSrc, len, encoder, RIJ_NR(pAES), RIJ_EKEYS(pAES), AESGCM_GHASH(pState),
         AESGCM_COUNTER(pState), AESGCM_ECOUNTER(pState), hkeys_old_order);

      // zeroizing 
      zeroize_256((Ipp32u*)hkeys_old_order, 12);
   }
   else {
      IppsRijndael128Spec* pAES = AESGCM_CIPHER(pState);
      Ipp8u* pCounter = AESGCM_COUNTER(pState);
      Ipp8u* pECounter = AESGCM_ECOUNTER(pState);
      __m256i pCounter256, pCounter256_1, pCounter256_2, pCounter256_3, pCounter256_4, pCounter256_5, pCounter256_6, pCounter256_7;
      __m256i block, block1, block2, block3, block4, block5, block6, block7;
      __m256i cipherText, cipherText_1, cipherText_2, cipherText_3, cipherText_4, cipherText_5, cipherText_6, cipherText_7;
      __m256i plainText, plainText_1, plainText_2, plainText_3, plainText_4, plainText_5, plainText_6, plainText_7;
      __m256i rpHash[8];
      __m256i HashKey[8];
      __m128i resultHash = _mm_setzero_si128(), block128, cipherText128, plainText128;
      __m256i tmpKey;

      // setting temporary data for incremention
      const __m256i increment1    = _mm256_loadu_si256((void*)_increment1); // increment by 1
      const __m256i increment2    = _mm256_loadu_si256((void*)_increment2); // increment by 2
      const __m256i increment4    = _mm256_loadu_si256((void*)_increment4); // increment by 4
      const __m256i increment8    = _mm256_loadu_si256((void*)_increment8); // increment by 8
      const __m256i increment16   = _mm256_loadu_si256((void*)_increment16); // increment by 16
      const __m256i shuffle_mask  = _mm256_loadu_si256((void*)swapBytes256);

      // vector is used to zeroizing 
      __m256i zero_256 = _mm256_setzero_si256();

      // setting some masks
      const __m128i shuff_mask_128 = _mm_loadu_si128((void*)_shuff_mask_128);
      const __m256i shuff_mask_256 = _mm256_loadu_si256((void*)_shuff_mask_256);

      // loading counters from memory
      __m128i lo = _mm_loadu_si128((void*)pCounter);
      IncrementCounter32(pCounter);
      __m128i hi = _mm_loadu_si128((void*)pCounter);
      pCounter256_7 = _mm256_setr_m128i(lo, hi);
      pCounter256 = pCounter256_7;
      IncrementRegister256(pCounter256_7, increment2, shuffle_mask);
      pCounter256_1 = pCounter256_7;
      IncrementRegister256(pCounter256_7, increment2, shuffle_mask);
      pCounter256_2 = pCounter256_7;
      IncrementRegister256(pCounter256_7, increment2, shuffle_mask);
      pCounter256_3 = pCounter256_7;
      IncrementRegister256(pCounter256_7, increment2, shuffle_mask);
      pCounter256_4 = pCounter256_7;
      IncrementRegister256(pCounter256_7, increment2, shuffle_mask);
      pCounter256_5 = pCounter256_7;
      IncrementRegister256(pCounter256_7, increment2, shuffle_mask);
      pCounter256_6 = pCounter256_7;
      IncrementRegister256(pCounter256_7, increment2, shuffle_mask);
      
      lo = _mm_loadu_si128((__m128i*)AESGCM_GHASH(pState));
      hi = _mm_setzero_si128();
      rpHash[0] = _mm256_setr_m128i(_mm_shuffle_epi8(lo, shuff_mask_128), hi);

      // setting hash keys
      Ipp8u *pkeys = AESGCM_HKEY(pState);
      for (int i = 0; i < 8; i++) {
         HashKey[i] = _mm256_setr_m128i(_mm_loadu_si128((void*)(pkeys+16)), _mm_loadu_si128((void*)pkeys));
         pkeys += 32;
      }

      while(len >= 16*BLOCK_SIZE) {
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES))));
         block = _mm256_xor_si256(pCounter256, tmpKey);
         block1 = _mm256_xor_si256(pCounter256_1, tmpKey);
         block2 = _mm256_xor_si256(pCounter256_2, tmpKey);
         block3 = _mm256_xor_si256(pCounter256_3, tmpKey);
         block4 = _mm256_xor_si256(pCounter256_4, tmpKey);
         block5 = _mm256_xor_si256(pCounter256_5, tmpKey);
         block6 = _mm256_xor_si256(pCounter256_6, tmpKey);
         block7 = _mm256_xor_si256(pCounter256_7, tmpKey);
         IncrementRegister256(pCounter256, increment16, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+1*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         block4 = _mm256_aesenc_epi128(block4, tmpKey);
         block5 = _mm256_aesenc_epi128(block5, tmpKey);
         block6 = _mm256_aesenc_epi128(block6, tmpKey);
         block7 = _mm256_aesenc_epi128(block7, tmpKey);
         IncrementRegister256(pCounter256_1, increment16, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+2*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         block4 = _mm256_aesenc_epi128(block4, tmpKey);
         block5 = _mm256_aesenc_epi128(block5, tmpKey);
         block6 = _mm256_aesenc_epi128(block6, tmpKey);
         block7 = _mm256_aesenc_epi128(block7, tmpKey);
         IncrementRegister256(pCounter256_2, increment16, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+3*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         block4 = _mm256_aesenc_epi128(block4, tmpKey);
         block5 = _mm256_aesenc_epi128(block5, tmpKey);
         block6 = _mm256_aesenc_epi128(block6, tmpKey);
         block7 = _mm256_aesenc_epi128(block7, tmpKey);
         IncrementRegister256(pCounter256_3, increment16, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+4*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         block4 = _mm256_aesenc_epi128(block4, tmpKey);
         block5 = _mm256_aesenc_epi128(block5, tmpKey);
         block6 = _mm256_aesenc_epi128(block6, tmpKey);
         block7 = _mm256_aesenc_epi128(block7, tmpKey);
         IncrementRegister256(pCounter256_4, increment16, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+5*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         block4 = _mm256_aesenc_epi128(block4, tmpKey);
         block5 = _mm256_aesenc_epi128(block5, tmpKey);
         block6 = _mm256_aesenc_epi128(block6, tmpKey);
         block7 = _mm256_aesenc_epi128(block7, tmpKey);
         IncrementRegister256(pCounter256_5, increment16, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+6*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         block4 = _mm256_aesenc_epi128(block4, tmpKey);
         block5 = _mm256_aesenc_epi128(block5, tmpKey);
         block6 = _mm256_aesenc_epi128(block6, tmpKey);
         block7 = _mm256_aesenc_epi128(block7, tmpKey);
         IncrementRegister256(pCounter256_6, increment16, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+7*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         block4 = _mm256_aesenc_epi128(block4, tmpKey);
         block5 = _mm256_aesenc_epi128(block5, tmpKey);
         block6 = _mm256_aesenc_epi128(block6, tmpKey);
         block7 = _mm256_aesenc_epi128(block7, tmpKey);
         IncrementRegister256(pCounter256_7, increment16, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+8*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         block4 = _mm256_aesenc_epi128(block4, tmpKey);
         block5 = _mm256_aesenc_epi128(block5, tmpKey);
         block6 = _mm256_aesenc_epi128(block6, tmpKey);
         block7 = _mm256_aesenc_epi128(block7, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+9*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         block4 = _mm256_aesenc_epi128(block4, tmpKey);
         block5 = _mm256_aesenc_epi128(block5, tmpKey);
         block6 = _mm256_aesenc_epi128(block6, tmpKey);
         block7 = _mm256_aesenc_epi128(block7, tmpKey);
         if (RIJ_NR(pAES) >= 12) {
            tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+10*16)));
            block = _mm256_aesenc_epi128(block, tmpKey);
            block1 = _mm256_aesenc_epi128(block1, tmpKey);
            block2 = _mm256_aesenc_epi128(block2, tmpKey);
            block3 = _mm256_aesenc_epi128(block3, tmpKey);
            block4 = _mm256_aesenc_epi128(block4, tmpKey);
            block5 = _mm256_aesenc_epi128(block5, tmpKey);
            block6 = _mm256_aesenc_epi128(block6, tmpKey);
            block7 = _mm256_aesenc_epi128(block7, tmpKey);
            tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+11*16)));
            block = _mm256_aesenc_epi128(block, tmpKey);
            block1 = _mm256_aesenc_epi128(block1, tmpKey);
            block2 = _mm256_aesenc_epi128(block2, tmpKey);
            block3 = _mm256_aesenc_epi128(block3, tmpKey);
            block4 = _mm256_aesenc_epi128(block4, tmpKey);
            block5 = _mm256_aesenc_epi128(block5, tmpKey);
            block6 = _mm256_aesenc_epi128(block6, tmpKey);
            block7 = _mm256_aesenc_epi128(block7, tmpKey);
            if (RIJ_NR(pAES) >= 14) {
               tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+12*16)));
               block = _mm256_aesenc_epi128(block, tmpKey);
               block1 = _mm256_aesenc_epi128(block1, tmpKey);
               block2 = _mm256_aesenc_epi128(block2, tmpKey);
               block3 = _mm256_aesenc_epi128(block3, tmpKey);
               block4 = _mm256_aesenc_epi128(block4, tmpKey);
               block5 = _mm256_aesenc_epi128(block5, tmpKey);
               block6 = _mm256_aesenc_epi128(block6, tmpKey);
               block7 = _mm256_aesenc_epi128(block7, tmpKey);
               tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+13*16)));
               block = _mm256_aesenc_epi128(block, tmpKey);
               block1 = _mm256_aesenc_epi128(block1, tmpKey);
               block2 = _mm256_aesenc_epi128(block2, tmpKey);
               block3 = _mm256_aesenc_epi128(block3, tmpKey);
               block4 = _mm256_aesenc_epi128(block4, tmpKey);
               block5 = _mm256_aesenc_epi128(block5, tmpKey);
               block6 = _mm256_aesenc_epi128(block6, tmpKey);
               block7 = _mm256_aesenc_epi128(block7, tmpKey);
            }
         }
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+RIJ_NR(pAES)*16))); 
         block = _mm256_aesenclast_epi128(block, tmpKey);
         block1 = _mm256_aesenclast_epi128(block1, tmpKey);
         block2 = _mm256_aesenclast_epi128(block2, tmpKey);
         block3 = _mm256_aesenclast_epi128(block3, tmpKey);
         block4 = _mm256_aesenclast_epi128(block4, tmpKey);
         block5 = _mm256_aesenclast_epi128(block5, tmpKey);
         block6 = _mm256_aesenclast_epi128(block6, tmpKey);
         block7 = _mm256_aesenclast_epi128(block7, tmpKey);

         // set ciphertext 
         plainText = _mm256_loadu_si256((void*)pSrc);
         cipherText = _mm256_xor_si256(plainText, block);
         plainText_1 = _mm256_loadu_si256((void*)(pSrc+2*BLOCK_SIZE));
         cipherText_1 = _mm256_xor_si256(plainText_1, block1);
         plainText_2 = _mm256_loadu_si256((void*)(pSrc+4*BLOCK_SIZE));
         cipherText_2 = _mm256_xor_si256(plainText_2, block2);
         plainText_3 = _mm256_loadu_si256((void*)(pSrc+6*BLOCK_SIZE));
         cipherText_3 = _mm256_xor_si256(plainText_3, block3);
         plainText_4 = _mm256_loadu_si256((void*)(pSrc+8*BLOCK_SIZE));
         cipherText_4 = _mm256_xor_si256(plainText_4, block4);
         plainText_5 = _mm256_loadu_si256((void*)(pSrc+10*BLOCK_SIZE));
         cipherText_5 = _mm256_xor_si256(plainText_5, block5);
         plainText_6 = _mm256_loadu_si256((void*)(pSrc+12*BLOCK_SIZE));
         cipherText_6 = _mm256_xor_si256(plainText_6, block6);
         plainText_7 = _mm256_loadu_si256((void*)(pSrc+14*BLOCK_SIZE));
         cipherText_7 = _mm256_xor_si256(plainText_7, block7);
         pSrc += 16*BLOCK_SIZE;
         _mm256_storeu_si256((void*)pDst, cipherText);
         _mm256_storeu_si256((void*)(pDst+2*BLOCK_SIZE), cipherText_1);
         _mm256_storeu_si256((void*)(pDst+4*BLOCK_SIZE), cipherText_2);
         _mm256_storeu_si256((void*)(pDst+6*BLOCK_SIZE), cipherText_3);
         _mm256_storeu_si256((void*)(pDst+8*BLOCK_SIZE), cipherText_4);
         _mm256_storeu_si256((void*)(pDst+10*BLOCK_SIZE), cipherText_5);
         _mm256_storeu_si256((void*)(pDst+12*BLOCK_SIZE), cipherText_6);
         _mm256_storeu_si256((void*)(pDst+14*BLOCK_SIZE), cipherText_7);
         pDst += 16*BLOCK_SIZE;

         // hash calculation stage
         rpHash[0] = _mm256_xor_si256(rpHash[0], _mm256_shuffle_epi8(plainText, shuff_mask_256));
         rpHash[1] = _mm256_shuffle_epi8(plainText_1, shuff_mask_256);
         rpHash[2] = _mm256_shuffle_epi8(plainText_2, shuff_mask_256);
         rpHash[3] = _mm256_shuffle_epi8(plainText_3, shuff_mask_256);
         rpHash[4] = _mm256_shuffle_epi8(plainText_4, shuff_mask_256);
         rpHash[5] = _mm256_shuffle_epi8(plainText_5, shuff_mask_256);
         rpHash[6] = _mm256_shuffle_epi8(plainText_6, shuff_mask_256);
         rpHash[7] = _mm256_shuffle_epi8(plainText_7, shuff_mask_256);
         resultHash = avx2_clmul_gcm16(rpHash, HashKey);

         len -= 16*BLOCK_SIZE;
      } // while(len >= 16*BLOCK_SIZE)

      if (len >= 8*BLOCK_SIZE) {
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES))));
         block = _mm256_xor_si256(pCounter256, tmpKey);
         block1 = _mm256_xor_si256(pCounter256_1, tmpKey);
         block2 = _mm256_xor_si256(pCounter256_2, tmpKey);
         block3 = _mm256_xor_si256(pCounter256_3, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+1*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         IncrementRegister256(pCounter256, increment8, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+2*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+3*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         IncrementRegister256(pCounter256_1, increment8, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+4*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+5*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         IncrementRegister256(pCounter256_2, increment8, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+6*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+7*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+8*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         IncrementRegister256(pCounter256_3, increment8, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+9*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         block2 = _mm256_aesenc_epi128(block2, tmpKey);
         block3 = _mm256_aesenc_epi128(block3, tmpKey);
         if (RIJ_NR(pAES) >= 12) {
            tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+10*16)));
            block = _mm256_aesenc_epi128(block, tmpKey);
            block1 = _mm256_aesenc_epi128(block1, tmpKey);
            block2 = _mm256_aesenc_epi128(block2, tmpKey);
            block3 = _mm256_aesenc_epi128(block3, tmpKey);
            tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+11*16)));
            block = _mm256_aesenc_epi128(block, tmpKey);
            block1 = _mm256_aesenc_epi128(block1, tmpKey);
            block2 = _mm256_aesenc_epi128(block2, tmpKey);
            block3 = _mm256_aesenc_epi128(block3, tmpKey);
            if (RIJ_NR(pAES) >= 14) {
               tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+12*16)));
               block = _mm256_aesenc_epi128(block, tmpKey);
               block1 = _mm256_aesenc_epi128(block1, tmpKey);
               block2 = _mm256_aesenc_epi128(block2, tmpKey);
               block3 = _mm256_aesenc_epi128(block3, tmpKey);
               tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+13*16)));
               block = _mm256_aesenc_epi128(block, tmpKey);
               block1 = _mm256_aesenc_epi128(block1, tmpKey);
               block2 = _mm256_aesenc_epi128(block2, tmpKey);
               block3 = _mm256_aesenc_epi128(block3, tmpKey);
            }
         }
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+RIJ_NR(pAES)*16))); 
         block = _mm256_aesenclast_epi128(block, tmpKey);
         block1 = _mm256_aesenclast_epi128(block1, tmpKey);
         block2 = _mm256_aesenclast_epi128(block2, tmpKey);
         block3 = _mm256_aesenclast_epi128(block3, tmpKey);

         // set ciphertext 
         plainText = _mm256_loadu_si256((void*)pSrc);
         cipherText = _mm256_xor_si256(plainText, block);
         plainText_1 = _mm256_loadu_si256((void*)(pSrc+2*BLOCK_SIZE));
         cipherText_1 = _mm256_xor_si256(plainText_1, block1);
         plainText_2 = _mm256_loadu_si256((void*)(pSrc+4*BLOCK_SIZE));
         cipherText_2 = _mm256_xor_si256(plainText_2, block2);
         plainText_3 = _mm256_loadu_si256((void*)(pSrc+6*BLOCK_SIZE));
         cipherText_3 = _mm256_xor_si256(plainText_3, block3);
         pSrc += 8*BLOCK_SIZE;
         _mm256_storeu_si256((void*)pDst, cipherText);
         _mm256_storeu_si256((void*)(pDst+2*BLOCK_SIZE), cipherText_1);
         _mm256_storeu_si256((void*)(pDst+4*BLOCK_SIZE), cipherText_2);
         _mm256_storeu_si256((void*)(pDst+6*BLOCK_SIZE), cipherText_3);
         pDst += 8*BLOCK_SIZE;

         // hash calculation stage
         rpHash[0] = _mm256_xor_si256(rpHash[0], _mm256_shuffle_epi8(plainText, shuff_mask_256));
         rpHash[1] = _mm256_shuffle_epi8(plainText_1, shuff_mask_256);
         rpHash[2] = _mm256_shuffle_epi8(plainText_2, shuff_mask_256);
         rpHash[3] = _mm256_shuffle_epi8(plainText_3, shuff_mask_256);
         resultHash = avx2_clmul_gcm8(rpHash, HashKey);

         len -= 8*BLOCK_SIZE;
      } //if (len >= 8*BLOCK_SIZE)

      if (len >= 4*BLOCK_SIZE) {
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES))));
         block = _mm256_xor_si256(pCounter256, tmpKey);
         block1 = _mm256_xor_si256(pCounter256_1, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+1*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+2*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         IncrementRegister256(pCounter256, increment4, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+3*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+4*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+5*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+6*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         IncrementRegister256(pCounter256_1, increment4, shuffle_mask);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+7*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+8*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+9*16)));
         block = _mm256_aesenc_epi128(block, tmpKey);
         block1 = _mm256_aesenc_epi128(block1, tmpKey);
         if (RIJ_NR(pAES) >= 12) {
            tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+10*16)));
            block = _mm256_aesenc_epi128(block, tmpKey);
            block1 = _mm256_aesenc_epi128(block1, tmpKey);
            tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+11*16)));
            block = _mm256_aesenc_epi128(block, tmpKey);
            block1 = _mm256_aesenc_epi128(block1, tmpKey);
            if (RIJ_NR(pAES) >= 14) {
               tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+12*16)));
               block = _mm256_aesenc_epi128(block, tmpKey);
               block1 = _mm256_aesenc_epi128(block1, tmpKey);
               tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+13*16)));
               block = _mm256_aesenc_epi128(block, tmpKey);
               block1 = _mm256_aesenc_epi128(block1, tmpKey);
            }
         }
         tmpKey = _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+RIJ_NR(pAES)*16))); 
         block = _mm256_aesenclast_epi128(block, tmpKey);
         block1 = _mm256_aesenclast_epi128(block1, tmpKey);

         // set ciphertext 
         plainText = _mm256_loadu_si256((void*)pSrc);
         cipherText = _mm256_xor_si256(plainText, block);
         plainText_1 = _mm256_loadu_si256((void*)(pSrc+2*BLOCK_SIZE));
         cipherText_1 = _mm256_xor_si256(plainText_1, block1);
         pSrc += 4*BLOCK_SIZE;
         _mm256_storeu_si256((void*)pDst, cipherText);
         _mm256_storeu_si256((void*)(pDst+2*BLOCK_SIZE), cipherText_1);
         pDst += 4*BLOCK_SIZE;
         // hash calculation stage
         rpHash[0] = _mm256_xor_si256(rpHash[0], _mm256_shuffle_epi8(plainText, shuff_mask_256));
         rpHash[1] = _mm256_shuffle_epi8(plainText_1, shuff_mask_256);
         resultHash = avx2_clmul_gcm4(rpHash, HashKey);
         len -= 4*BLOCK_SIZE;
      } //if (len >= 4*BLOCK_SIZE)

      if (len >= 2*BLOCK_SIZE) {
         block = _mm256_xor_si256(pCounter256, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)))));
         block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+1*16))));
         block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+2*16))));
         block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+3*16))));
         block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+4*16))));
         IncrementRegister256(pCounter256, increment2, shuffle_mask);
         block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+5*16))));
         block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+6*16))));
         block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+7*16))));
         block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+8*16))));
         block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+9*16))));
         if (RIJ_NR(pAES) >= 12) {
            block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+10*16))));
            block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+11*16))));
            if (RIJ_NR(pAES) >= 14) {
               block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+12*16))));
               block = _mm256_aesenc_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+13*16))));
            }
         } 
         block = _mm256_aesenclast_epi128(block, _mm256_broadcastsi128_si256(_mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+RIJ_NR(pAES)*16))));

         // set ciphertext 
         plainText = _mm256_loadu_si256((void*)pSrc);
         cipherText = _mm256_xor_si256(plainText, block);
         pSrc += 2*BLOCK_SIZE;
         _mm256_storeu_si256((void*)pDst, cipherText);
         pDst += 2*BLOCK_SIZE;
         // hash calculation stage
         rpHash[0] = _mm256_xor_si256(rpHash[0], _mm256_shuffle_epi8(plainText, shuff_mask_256));
         resultHash = avx2_clmul_gcm2(rpHash, HashKey);
         len -= 2*BLOCK_SIZE;
      }

      if (len >= BLOCK_SIZE) {
         block128 = _mm_xor_si128(_mm256_castsi256_si128(pCounter256), _mm_loadu_si128((void*)(RIJ_EKEYS(pAES))));
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+1*16)));
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+2*16)));
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+3*16)));
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+4*16)));
         IncrementRegister256(pCounter256, increment1, shuffle_mask);
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+5*16)));
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+6*16)));
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+7*16)));
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+8*16)));
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+9*16)));
         if (RIJ_NR(pAES) >= 12) {
            block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+10*16)));
            block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+11*16)));
            if (RIJ_NR(pAES) >= 14) {
               block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+12*16)));
               block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+13*16)));
            }
         } 
         block128 = _mm_aesenclast_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+RIJ_NR(pAES)*16)));

         // set ciphertext 
         plainText128 = _mm_loadu_si128((void*)pSrc);
         cipherText128 = _mm_xor_si128(plainText128, block128);
         pSrc += BLOCK_SIZE;
         _mm_storeu_si128((void*)pDst, cipherText128);
         pDst += BLOCK_SIZE;
         // hash calculation stage
         HashKey[0] = _mm256_setr_m128i(_mm_loadu_si128((void*)(AESGCM_HKEY(pState))), _mm_loadu_si128((void*)(AESGCM_HKEY(pState))));
         rpHash[0] = _mm256_xor_si256(rpHash[0], _mm256_shuffle_epi8(_mm256_broadcastsi128_si256(plainText128), shuff_mask_256));
         resultHash = avx2_clmul_gcm(rpHash, HashKey);
         len -= BLOCK_SIZE;
      }

      //decrypt the remainder
      block128 = _mm_xor_si128(_mm256_castsi256_si128(pCounter256), _mm_loadu_si128((void*)(RIJ_EKEYS(pAES))));
      block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+1*16)));
      block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+2*16)));
      block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+3*16)));
      block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+4*16)));
      block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+5*16)));
      block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+6*16)));
      block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+7*16)));
      block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+8*16)));
      block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+9*16)));
      if (RIJ_NR(pAES) >= 12) {
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+10*16)));
         block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+11*16)));
         if (RIJ_NR(pAES) >= 14) {
            block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+12*16)));
            block128 = _mm_aesenc_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+13*16)));
         }
      } 
      block128 = _mm_aesenclast_si128(block128, _mm_loadu_si128((void*)(RIJ_EKEYS(pAES)+RIJ_NR(pAES)*16)));

      // store data to the memory
      _mm_storeu_si128((void*)pECounter, block128);
      _mm_storeu_si128((void*)pCounter, _mm256_castsi256_si128(pCounter256));
      resultHash = _mm_shuffle_epi8(resultHash, shuff_mask_128);
      _mm_storeu_si128((void*)(AESGCM_GHASH(pState)), resultHash);

      // HKeys zeroizing
      for (int i = 0; i < 8; i++)
         _mm256_storeu_si256((HashKey+i), zero_256);
      tmpKey = _mm256_setzero_si256();
   } // if (len < 256)
} 
#endif /* #if (_IPP==_IPP_H9) || (_IPP32E==_IPP32E_L9) */
