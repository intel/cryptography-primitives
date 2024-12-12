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
//     AES GCM AVX2
//     Internal Functions Implementations
//
*/

#ifndef __AES_GCM_AVX2_H_
#define __AES_GCM_AVX2_H_

#include "owndefs.h"
#include "owncp.h"
#include "pcpaesauthgcm.h"
#include "pcptool.h"

#if (_IPP==_IPP_H9) || (_IPP32E==_IPP32E_L9)

#ifdef __GNUC__
#define ASM(a) __asm__(a);
#else
#define ASM(a)
#endif

/*
// Zeroes the memory by 32 bit parts,
// because "epi32" is the minimal available granularity for avx2 store instructions.
// input:
//   Ipp32u* out - pointer to the memory that needs to be zeroize
//   int len - length of the "out" array, in 32-bit chunks
*/
static __NOINLINE
void zeroize_256(Ipp32u* out, int len)
{
#if defined(__GNUC__)
   // Avoid dead code elimination for GNU compilers
   ASM("");
#endif
   __m256i T = _mm256_setzero_si256();
   int i;
   int tmp[8];
   int rest = len % 8;
   if (rest == 0)
      for(i=0; i<8; i++)
         tmp[i] = (int)0xFFFFFFFF;
   else {
      for(i=0; i<rest; i++)
         tmp[i] = (int)0xFFFFFFFF;
      for(i=rest; i<8; i++)
         tmp[i] = 0;
   }
   __m256i mask = _mm256_set_epi32(tmp[7], tmp[6], tmp[5], tmp[4], tmp[3], tmp[2], tmp[1], tmp[0]);
   for(i=0; i<len-7; i+=8)
      _mm256_storeu_si256((void*)(out+i), T);
   if (i < len)
      _mm256_maskstore_epi32((void*)(out+i), mask, T);
}

#define MAX_NK 15 //the largest possible number of keys

#define SHUFD_MASK 78 // 01001110b

//is used to increment two 128-bit words in a 256-bit register
#define IncrementRegister256(t_block, t_incr, t_shuffle_mask) \
   t_block = _mm256_shuffle_epi8(t_block, t_shuffle_mask); \
   (t_block) = _mm256_add_epi32(t_block, t_incr);            \
   (t_block) = _mm256_shuffle_epi8(t_block, t_shuffle_mask)

// these constants are used to increment two 128-bit words in a 256-bit register
__ALIGN32 static const Ipp32u _increment1[] = {0, 0, 0, 1, 0, 0, 0, 1};
__ALIGN32 static const Ipp32u _increment2[] = {0, 0, 0, 2, 0, 0, 0, 2};
__ALIGN32 static const Ipp32u _increment4[] = {0, 0, 0, 4, 0, 0, 0, 4};
__ALIGN32 static const Ipp32u _increment8[] = {0, 0, 0, 8, 0, 0, 0, 8};
__ALIGN32 static const Ipp32u _increment16[] = {0, 0, 0, 16, 0, 0, 0, 16};
__ALIGN32 static const Ipp8u swapBytes256[] = {
   16, 17, 18, 19, 20, 21, 22, 23,
   24, 25, 26, 27, 31, 30, 29, 28,
   0, 1, 2, 3, 4, 5, 6, 7,
   8, 9, 10, 11, 15, 14, 13, 12
};

// shuffle masks
__ALIGN32 static const Ipp8u _shuff_mask_128[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
__ALIGN32 static const Ipp8u _shuff_mask_256[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};

/*
// performs Karatsuba carry-less multiplication
// input:
//   __m256i GH - contains current GHASH
//   const __m256i HK - contains hashed keys
// input/output:
//   __m256i *tmpX0, __m128i *tmpX5 - contains temporary data for multiplication
// output:
//   __m256i part of the multiplication result
*/
__IPPCP_INLINE __m256i avx2_internal_mul(__m256i GH, const __m256i HK, __m256i *tmpX0, __m256i *tmpX5) {
   __m256i tmpX2, tmpX3, tmpX4;

   tmpX2 = _mm256_shuffle_epi32 (GH, SHUFD_MASK);
   tmpX3 = _mm256_shuffle_epi32 (HK, SHUFD_MASK);
   tmpX2 = _mm256_xor_si256(tmpX2, GH);
   tmpX3 = _mm256_xor_si256(tmpX3, HK);
   tmpX4 = _mm256_clmulepi64_epi128(GH, HK, 0x11);
   *tmpX0 = _mm256_xor_si256(*tmpX0, tmpX4);
   tmpX4 = _mm256_clmulepi64_epi128(GH, HK, 0x00);
   *tmpX5 = _mm256_xor_si256(*tmpX5, tmpX4);
   return _mm256_clmulepi64_epi128(tmpX2, tmpX3, 0x00);
}

/*
// performs the reduction phase after carry-less multiplication
// input/output:
//   __m128i *hash0, __m128i *hash1 - contains the two parts of the GHASH
*/
__IPPCP_INLINE void reduction(__m128i *hash0, __m128i *hash1) {
   __m128i T1, T2, T3;

   //first phase of the reduction
   T1 = *hash1; //copy GH into T1, T2, T3
   T2 = *hash1;
   T3 = *hash1;
   T1 = _mm_slli_epi64 (T1, 63); //packed left shifting << 63
   T2 = _mm_slli_epi64 (T2, 62); //packed left shifting << 62
   T3 = _mm_slli_epi64 (T3, 57); //packed left shifting << 57
   T1 = _mm_xor_si128(T1, T2); //xor the shifted versions
   T1 = _mm_xor_si128(T1, T3);
   T2 = T1;
   T2 = _mm_slli_si128 (T2, 8); //shift-L T2 2 DWs
   T1 = _mm_srli_si128 (T1, 8); //shift-R T1 2 DWs
   *hash1 = _mm_xor_si128(*hash1, T2); //first phase of the reduction complete
   *hash0 = _mm_xor_si128(*hash0, T1); //save the lost MS 1-2-7 bits from first phase

   //second phase of the reduction
   T2 = *hash1;
   T2 = _mm_srli_epi64(T2, 5); //packed right shifting >> 5
   T2 = _mm_xor_si128(T2, *hash1); //xor shifted versions
   T2 = _mm_srli_epi64(T2, 1); //packed right shifting >> 1
   T2 = _mm_xor_si128(T2, *hash1); //xor shifted versions
   T2 = _mm_srli_epi64(T2, 1); //packed right shifting >> 1
   *hash1 = _mm_xor_si128(*hash1, T2); //second phase of the reduction complete
}

/*
// avx2_clmul_gcm16 performs the hash calculation with 256-bit registers for 16 blocks
// GH order - 0, 1 | 2, 3 | 4, 5 | 6, 7 | 8, 9 | 10, 11 | 12, 13 | 14, 15
// HK order - 1, 0 | 3, 2 | 5, 4 | 7, 6 | 9, 8 | 11, 10 | 13, 12 | 15, 14
// input:
//    const __m256i *HK - contains hashed keys
// input/output:
//    __m256i *GH - contains GHASH. Will be overwritten in this function
// output:
//    __m128i GH[0]
*/
__IPPCP_INLINE __m128i avx2_clmul_gcm16(__m256i *GH, const __m256i *HK) {
   __m256i tmpX0, tmpX2, tmpX3, tmpX4, tmpX5;
   tmpX2 = _mm256_shuffle_epi32 (GH[0], SHUFD_MASK);
   tmpX3 = _mm256_shuffle_epi32 (HK[7], SHUFD_MASK);
   tmpX2 = _mm256_xor_si256(tmpX2, GH[0]);
   tmpX3 = _mm256_xor_si256(tmpX3, HK[7]);
   tmpX0 = _mm256_clmulepi64_epi128 (GH[0], HK[7], 0x11);
   tmpX5 = _mm256_clmulepi64_epi128 (GH[0], HK[7], 0x00);
   GH[0] = _mm256_clmulepi64_epi128 (tmpX2, tmpX3, 0x00);

   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[1], HK[6], &tmpX0, &tmpX5));
   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[2], HK[5], &tmpX0, &tmpX5));
   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[3], HK[4], &tmpX0, &tmpX5));
   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[4], HK[3], &tmpX0, &tmpX5));
   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[5], HK[2], &tmpX0, &tmpX5));
   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[6], HK[1], &tmpX0, &tmpX5));
   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[7], HK[0], &tmpX0, &tmpX5));

   GH[0] = _mm256_xor_si256(GH[0], tmpX0);
   tmpX2 = _mm256_xor_si256(GH[0], tmpX5);
   tmpX4 = _mm256_slli_si256(tmpX2, 8);
   tmpX2 = _mm256_srli_si256(tmpX2, 8);
   tmpX5 = _mm256_xor_si256(tmpX5, tmpX4); //
   tmpX0 = _mm256_xor_si256(tmpX0, tmpX2); // tmpX0:tmpX5> holds the result of the accumulated carry-less multiplications

   __m128i T0, T1;
   T0 = _mm_xor_si128(_mm256_extractf128_si256(tmpX0, 0), _mm256_extractf128_si256(tmpX0, 1));
   T1 = _mm_xor_si128(_mm256_extractf128_si256(tmpX5, 0), _mm256_extractf128_si256(tmpX5, 1));

   // reduction phase
   reduction(&T0, &T1);

   GH[0] = _mm256_setr_m128i(_mm_xor_si128(T1, T0), _mm_setzero_si128()); //the result is in GH
   return _mm_xor_si128(T1, T0);
}

/*
// avx2_clmul_gcm8 performs the hash calculation with 256-bit registers for 8 blocks
// GH order - 0, 1 | 2, 3 | 4, 5 | 6, 7
// HK order - 1, 0 | 3, 2 | 5, 4 | 7, 6
// input:
//    const __m256i *HK - contains hashed keys
// input/output:
//    __m256i *GH - contains GHASH. Will be overwritten in this function
// output:
//    __m128i GH[0]
*/
__IPPCP_INLINE __m128i avx2_clmul_gcm8(__m256i *GH, const __m256i *HK) {
   __m256i tmpX0, tmpX2, tmpX3, tmpX4, tmpX5;
   tmpX2 = _mm256_shuffle_epi32 (GH[0], SHUFD_MASK);
   tmpX3 = _mm256_shuffle_epi32 (HK[3], SHUFD_MASK);
   tmpX2 = _mm256_xor_si256(tmpX2, GH[0]);
   tmpX3 = _mm256_xor_si256(tmpX3, HK[3]);
   tmpX0 = _mm256_clmulepi64_epi128 (GH[0], HK[3], 0x11);
   tmpX5 = _mm256_clmulepi64_epi128 (GH[0], HK[3], 0x00);
   GH[0] = _mm256_clmulepi64_epi128 (tmpX2, tmpX3, 0x00);

   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[1], HK[2], &tmpX0, &tmpX5));
   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[2], HK[1], &tmpX0, &tmpX5));
   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[3], HK[0], &tmpX0, &tmpX5));

   GH[0] = _mm256_xor_si256(GH[0], tmpX0);
   tmpX2 = _mm256_xor_si256(GH[0], tmpX5);
   tmpX4 = _mm256_slli_si256(tmpX2, 8);
   tmpX2 = _mm256_srli_si256(tmpX2, 8);
   tmpX5 = _mm256_xor_si256(tmpX5, tmpX4); //
   tmpX0 = _mm256_xor_si256(tmpX0, tmpX2); // tmpX0:tmpX5> holds the result of the accumulated carry-less multiplications

   __m128i T0, T1;
   T0 = _mm_xor_si128(_mm256_extractf128_si256(tmpX0, 0), _mm256_extractf128_si256(tmpX0, 1));
   T1 = _mm_xor_si128(_mm256_extractf128_si256(tmpX5, 0), _mm256_extractf128_si256(tmpX5, 1));

   // reduction phase
   reduction(&T0, &T1);

   GH[0] = _mm256_setr_m128i(_mm_xor_si128(T1, T0), _mm_setzero_si128()); //the result is in GH
   return _mm_xor_si128(T1, T0);
}

/*
// avx2_clmul_gcm4 performs the hash calculation with 256-bit registers for 4 blocks
// GH order - 0, 1 | 2, 3
// HK order - 1, 0 | 3, 2
// input:
//    const __m256i *HK - contains hashed keys
// input/output:
//    __m256i *GH - contains GHASH. Will be overwritten in this function
// output:
//    __m128i GH[0]
*/
__IPPCP_INLINE __m128i avx2_clmul_gcm4(__m256i *GH, const __m256i *HK) {
   __m256i tmpX0, tmpX2, tmpX3, tmpX4, tmpX5;
   tmpX2 = _mm256_shuffle_epi32 (GH[0], SHUFD_MASK);
   tmpX3 = _mm256_shuffle_epi32 (HK[1], SHUFD_MASK);
   tmpX2 = _mm256_xor_si256(tmpX2, GH[0]);
   tmpX3 = _mm256_xor_si256(tmpX3, HK[1]);
   tmpX0 = _mm256_clmulepi64_epi128 (GH[0], HK[1], 0x11);
   tmpX5 = _mm256_clmulepi64_epi128 (GH[0], HK[1], 0x00);
   GH[0] = _mm256_clmulepi64_epi128 (tmpX2, tmpX3, 0x00);

   GH[0] = _mm256_xor_si256(GH[0], avx2_internal_mul(GH[1], HK[0], &tmpX0, &tmpX5));

   GH[0] = _mm256_xor_si256(GH[0], tmpX0);
   tmpX2 = _mm256_xor_si256(GH[0], tmpX5);
   tmpX4 = _mm256_slli_si256(tmpX2, 8);
   tmpX2 = _mm256_srli_si256(tmpX2, 8);
   tmpX5 = _mm256_xor_si256(tmpX5, tmpX4); //
   tmpX0 = _mm256_xor_si256(tmpX0, tmpX2); // tmpX0:tmpX5> holds the result of the accumulated carry-less multiplications

   __m128i T0, T1;
   T0 = _mm_xor_si128(_mm256_extractf128_si256(tmpX0, 0), _mm256_extractf128_si256(tmpX0, 1));
   T1 = _mm_xor_si128(_mm256_extractf128_si256(tmpX5, 0), _mm256_extractf128_si256(tmpX5, 1));

   // reduction phase
   reduction(&T0, &T1);

   GH[0] = _mm256_setr_m128i(_mm_xor_si128(T1, T0), _mm_setzero_si128()); //the result is in GH

   return _mm_xor_si128(T1, T0);
}

/*
// avx2_clmul_gcm2 performs the hash calculation with 256-bit registers for 2 blocks
// GH order - 0, 1
// HK order - 1, 0
// input:
//    const __m256i *HK - contains hashed keys
// input/output:
//    __m256i *GH - contains GHASH. Will be overwritten in this function
// output:
//    __m128i GH[0]
*/
__IPPCP_INLINE __m128i avx2_clmul_gcm2(__m256i *GH, const __m256i *HK) {
   __m256i tmpX0, tmpX2, tmpX3, tmpX4, tmpX5;
   tmpX2 = _mm256_shuffle_epi32 (GH[0], SHUFD_MASK);
   tmpX3 = _mm256_shuffle_epi32 (HK[0], SHUFD_MASK);
   tmpX2 = _mm256_xor_si256(tmpX2, GH[0]);
   tmpX3 = _mm256_xor_si256(tmpX3, HK[0]);
   tmpX0 = _mm256_clmulepi64_epi128 (GH[0], HK[0], 0x11);
   tmpX5 = _mm256_clmulepi64_epi128 (GH[0], HK[0], 0x00);
   GH[0] = _mm256_clmulepi64_epi128 (tmpX2, tmpX3, 0x00);

   GH[0] = _mm256_xor_si256(GH[0], tmpX0);
   tmpX2 = _mm256_xor_si256(GH[0], tmpX5);
   tmpX4 = _mm256_slli_si256(tmpX2, 8);
   tmpX2 = _mm256_srli_si256(tmpX2, 8);
   tmpX5 = _mm256_xor_si256(tmpX5, tmpX4); //
   tmpX0 = _mm256_xor_si256(tmpX0, tmpX2); // tmpX0:tmpX5> holds the result of the accumulated carry-less multiplications

   __m128i T0, T1;
   T0 = _mm_xor_si128(_mm256_extractf128_si256(tmpX0, 0), _mm256_extractf128_si256(tmpX0, 1));
   T1 = _mm_xor_si128(_mm256_extractf128_si256(tmpX5, 0), _mm256_extractf128_si256(tmpX5, 1));

   // reduction phase
   reduction(&T0, &T1);

   GH[0] = _mm256_setr_m128i(_mm_xor_si128(T1, T0), _mm_setzero_si128()); //the result is in GH
   return _mm_xor_si128(T1, T0);
}

/*
// avx2_clmul_gcm performs the hash calculation with 256-bit registers for 1 blocks
// GH order - 0
// HK order - 0
// input:
//    const __m256i *HK - contains hashed keys
// input/output:
//    __m256i *GH - contains GHASH. Will be overwritten in this function
// output:
//    __m128i GH[0]
*/
__IPPCP_INLINE __m128i avx2_clmul_gcm(__m256i *GH, const __m256i *HK) {
   __m256i tmpX0, tmpX2, tmpX3, tmpX4, tmpX5;
   tmpX2 = _mm256_shuffle_epi32 (GH[0], SHUFD_MASK);
   tmpX3 = _mm256_shuffle_epi32 (HK[0], SHUFD_MASK);
   tmpX2 = _mm256_xor_si256(tmpX2, GH[0]);
   tmpX3 = _mm256_xor_si256(tmpX3, HK[0]);
   tmpX0 = _mm256_clmulepi64_epi128 (GH[0], HK[0], 0x11);
   tmpX5 = _mm256_clmulepi64_epi128 (GH[0], HK[0], 0x00);
   GH[0] = _mm256_clmulepi64_epi128 (tmpX2, tmpX3, 0x00);

   GH[0] = _mm256_xor_si256(GH[0], tmpX0);
   tmpX2 = _mm256_xor_si256(GH[0], tmpX5);
   tmpX4 = _mm256_slli_si256(tmpX2, 8);
   tmpX2 = _mm256_srli_si256(tmpX2, 8);
   tmpX5 = _mm256_xor_si256(tmpX5, tmpX4); //
   tmpX0 = _mm256_xor_si256(tmpX0, tmpX2); // tmpX0:tmpX5> holds the result of the accumulated carry-less multiplications

   __m128i T0, T1;
   T0 = _mm256_extractf128_si256(tmpX0, 0);
   T1 = _mm256_extractf128_si256(tmpX5, 0);

   // reduction phase
   reduction(&T0, &T1);

   GH[0] = _mm256_setr_m128i(_mm_xor_si128(T1, T0), _mm_setzero_si128()); //the result is in GH
   return _mm_xor_si128(T1, T0);
}

#endif /* #if(_IPP==_IPP_H9) || (_IPP32E==_IPP32E_L9) */

#endif /* __AES_GCM_AVX2_H_ */
