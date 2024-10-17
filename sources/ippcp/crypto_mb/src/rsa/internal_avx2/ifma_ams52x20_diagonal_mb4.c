/*************************************************************************
 * Copyright (C) 2019-2024 Intel Corporation
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

#include <internal/common/ifma_defs.h>

/*
For squaring, an optimized approach is utilized. As an example, suppose we are multiplying two 4-digit numbers:
                                    | a3 | a2 | a1 | a0 |
                                    | b3 | b2 | b1 | b0 |
                                  X______________________

                | a3 * b3 | a2 * b2 | a1 * b1 | a0 * b0 |
                     | a3 * b2 | a2 * b1 | a1 * b0 |
                     | a2 * b3 | a1 * b2 | a0 * b1 |
                          | a3 * b1 | a2 * b0 |
                          | a1 * b3 | a0 * b2 |
                               | a3 * b0 |
                               | a0 * b3 |

This operation is realized with 4x4=16 digit-wise multiplications. When a=b (for squaring), multiplication operation is optimizes as follows:
                                    | a3 | a2 | a1 | a0 |
                                    | a3 | a2 | a1 | a0 |
                                  X______________________

                | a3 * a3 | a2 * a2 | a1 * a1 | a0 * a0 |
            2*       | a3 * a2 | a2 * a1 | a1 * a0 |

            2*            | a3 * a1 | a2 * a0 |

            2*                 | a3 * a0 |

This operation is realized with 10 digit-wise multiplications. For an n-digit squaring operation, (n^2-n)/2 less digit-wise multiplications are
required. The number of digit-wise multiplications for n-digit squaring can be calculated with the following equation:

    n^2 - (n^2-n)/2

multiplication by 2 operations are realized with add64 instructions.
*/

#if ((_MBX == _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

#include <internal/rsa/avxifma_ams.h>

static void ams52x20_square_diagonal_mb4(__m256i *res, const int64u *inpA_mb)
{
   const __m256i *inpA = (const __m256i *)inpA_mb;
   register __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8, AL;
   const int N             = 20;
   const __m256i zero_simd = _mm256_setzero_si256();

   // 1st triangle - sum the products, double and square
   r0 = zero_simd;

   res[0]  = _mm256_madd52lo_epu64(r0, inpA[0], inpA[0]);
   r1      = zero_simd;
   r2      = zero_simd;
   r3      = zero_simd;
   r4      = zero_simd;
   r5      = zero_simd;
   r6      = zero_simd;
   r7      = zero_simd;
   r8      = zero_simd;
   AL      = inpA[0];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[1]); // Sum(1)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[2]); // Sum(2)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[3]); // Sum(3)
   r3      = _mm256_madd52lo_epu64(r3, AL, inpA[4]); // Sum(4)
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[5]); // Sum(5)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[6]); // Sum(6)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[7]); // Sum(7)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[8]); // Sum(8)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[1]); // Sum(1)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[2]); // Sum(2)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[3]); // Sum(3)
   r4      = _mm256_madd52hi_epu64(r4, AL, inpA[4]); // Sum(4)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[5]); // Sum(5)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[6]); // Sum(6)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[7]); // Sum(7)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[8]); // Sum(8)
   AL      = inpA[1];
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[2]); // Sum(3)
   r3      = _mm256_madd52lo_epu64(r3, AL, inpA[3]); // Sum(4)
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[4]); // Sum(5)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[5]); // Sum(6)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[6]); // Sum(7)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[7]); // Sum(8)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[2]); // Sum(3)
   r4      = _mm256_madd52hi_epu64(r4, AL, inpA[3]); // Sum(4)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[4]); // Sum(5)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[5]); // Sum(6)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[6]); // Sum(7)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[7]); // Sum(8)
   AL      = inpA[2];
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[3]); // Sum(5)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[4]); // Sum(6)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[5]); // Sum(7)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[6]); // Sum(8)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[3]); // Sum(5)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[4]); // Sum(6)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[5]); // Sum(7)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[6]); // Sum(8)
   AL      = inpA[3];
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[4]);      // Sum(7)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[5]);      // Sum(8)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[4]);      // Sum(7)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[5]);      // Sum(8)
   r0      = _mm256_add_epi64(r0, r0);                    // Double(1)
   r0      = _mm256_madd52hi_epu64(r0, inpA[0], inpA[0]); // Add square(1)
   res[1]  = r0;
   r1      = _mm256_add_epi64(r1, r1);                    // Double(2)
   r1      = _mm256_madd52lo_epu64(r1, inpA[1], inpA[1]); // Add square(2)
   res[2]  = r1;
   r2      = _mm256_add_epi64(r2, r2);                    // Double(3)
   r2      = _mm256_madd52hi_epu64(r2, inpA[1], inpA[1]); // Add square(3)
   res[3]  = r2;
   r3      = _mm256_add_epi64(r3, r3);                    // Double(4)
   r3      = _mm256_madd52lo_epu64(r3, inpA[2], inpA[2]); // Add square(4)
   res[4]  = r3;
   r4      = _mm256_add_epi64(r4, r4);                    // Double(5)
   r4      = _mm256_madd52hi_epu64(r4, inpA[2], inpA[2]); // Add square(5)
   res[5]  = r4;
   r5      = _mm256_add_epi64(r5, r5);                    // Double(6)
   r5      = _mm256_madd52lo_epu64(r5, inpA[3], inpA[3]); // Add square(6)
   res[6]  = r5;
   r6      = _mm256_add_epi64(r6, r6);                    // Double(7)
   r6      = _mm256_madd52hi_epu64(r6, inpA[3], inpA[3]); // Add square(7)
   res[7]  = r6;
   r7      = _mm256_add_epi64(r7, r7);                    // Double(8)
   r7      = _mm256_madd52lo_epu64(r7, inpA[4], inpA[4]); // Add square(8)
   res[8]  = r7;
   r0      = r8;
   r1      = zero_simd;
   r2      = zero_simd;
   r3      = zero_simd;
   r4      = zero_simd;
   r5      = zero_simd;
   r6      = zero_simd;
   r7      = zero_simd;
   r8      = zero_simd;
   AL      = inpA[0];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[9]);  // Sum(9)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[10]); // Sum(10)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[11]); // Sum(11)
   r3      = _mm256_madd52lo_epu64(r3, AL, inpA[12]); // Sum(12)
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[13]); // Sum(13)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[14]); // Sum(14)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[15]); // Sum(15)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[16]); // Sum(16)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[9]);  // Sum(9)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[10]); // Sum(10)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[11]); // Sum(11)
   r4      = _mm256_madd52hi_epu64(r4, AL, inpA[12]); // Sum(12)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[13]); // Sum(13)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[14]); // Sum(14)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[15]); // Sum(15)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[16]); // Sum(16)
   AL      = inpA[1];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[8]);  // Sum(9)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[9]);  // Sum(10)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[10]); // Sum(11)
   r3      = _mm256_madd52lo_epu64(r3, AL, inpA[11]); // Sum(12)
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[12]); // Sum(13)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[13]); // Sum(14)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[14]); // Sum(15)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[15]); // Sum(16)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[8]);  // Sum(9)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[9]);  // Sum(10)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[10]); // Sum(11)
   r4      = _mm256_madd52hi_epu64(r4, AL, inpA[11]); // Sum(12)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[12]); // Sum(13)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[13]); // Sum(14)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[14]); // Sum(15)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[15]); // Sum(16)
   AL      = inpA[2];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[7]);  // Sum(9)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[8]);  // Sum(10)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[9]);  // Sum(11)
   r3      = _mm256_madd52lo_epu64(r3, AL, inpA[10]); // Sum(12)
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[11]); // Sum(13)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[12]); // Sum(14)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[13]); // Sum(15)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[14]); // Sum(16)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[7]);  // Sum(9)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[8]);  // Sum(10)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[9]);  // Sum(11)
   r4      = _mm256_madd52hi_epu64(r4, AL, inpA[10]); // Sum(12)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[11]); // Sum(13)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[12]); // Sum(14)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[13]); // Sum(15)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[14]); // Sum(16)
   AL      = inpA[3];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[6]);  // Sum(9)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[7]);  // Sum(10)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[8]);  // Sum(11)
   r3      = _mm256_madd52lo_epu64(r3, AL, inpA[9]);  // Sum(12)
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[10]); // Sum(13)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[11]); // Sum(14)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[12]); // Sum(15)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[13]); // Sum(16)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[6]);  // Sum(9)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[7]);  // Sum(10)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[8]);  // Sum(11)
   r4      = _mm256_madd52hi_epu64(r4, AL, inpA[9]);  // Sum(12)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[10]); // Sum(13)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[11]); // Sum(14)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[12]); // Sum(15)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[13]); // Sum(16)
   AL      = inpA[4];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[5]);  // Sum(9)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[6]);  // Sum(10)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[7]);  // Sum(11)
   r3      = _mm256_madd52lo_epu64(r3, AL, inpA[8]);  // Sum(12)
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[9]);  // Sum(13)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[10]); // Sum(14)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[11]); // Sum(15)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[12]); // Sum(16)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[5]);  // Sum(9)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[6]);  // Sum(10)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[7]);  // Sum(11)
   r4      = _mm256_madd52hi_epu64(r4, AL, inpA[8]);  // Sum(12)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[9]);  // Sum(13)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[10]); // Sum(14)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[11]); // Sum(15)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[12]); // Sum(16)
   AL      = inpA[5];
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[6]);  // Sum(11)
   r3      = _mm256_madd52lo_epu64(r3, AL, inpA[7]);  // Sum(12)
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[8]);  // Sum(13)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[9]);  // Sum(14)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[10]); // Sum(15)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[11]); // Sum(16)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[6]);  // Sum(11)
   r4      = _mm256_madd52hi_epu64(r4, AL, inpA[7]);  // Sum(12)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[8]);  // Sum(13)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[9]);  // Sum(14)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[10]); // Sum(15)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[11]); // Sum(16)
   AL      = inpA[6];
   r4      = _mm256_madd52lo_epu64(r4, AL, inpA[7]);  // Sum(13)
   r5      = _mm256_madd52lo_epu64(r5, AL, inpA[8]);  // Sum(14)
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[9]);  // Sum(15)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[10]); // Sum(16)
   r5      = _mm256_madd52hi_epu64(r5, AL, inpA[7]);  // Sum(13)
   r6      = _mm256_madd52hi_epu64(r6, AL, inpA[8]);  // Sum(14)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[9]);  // Sum(15)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[10]); // Sum(16)
   AL      = inpA[7];
   r6      = _mm256_madd52lo_epu64(r6, AL, inpA[8]);      // Sum(15)
   r7      = _mm256_madd52lo_epu64(r7, AL, inpA[9]);      // Sum(16)
   r7      = _mm256_madd52hi_epu64(r7, AL, inpA[8]);      // Sum(15)
   r8      = _mm256_madd52hi_epu64(r8, AL, inpA[9]);      // Sum(16)
   r0      = _mm256_add_epi64(r0, r0);                    // Double(9)
   r0      = _mm256_madd52hi_epu64(r0, inpA[4], inpA[4]); // Add square(9)
   res[9]  = r0;
   r1      = _mm256_add_epi64(r1, r1);                    // Double(10)
   r1      = _mm256_madd52lo_epu64(r1, inpA[5], inpA[5]); // Add square(10)
   res[10] = r1;
   r2      = _mm256_add_epi64(r2, r2);                    // Double(11)
   r2      = _mm256_madd52hi_epu64(r2, inpA[5], inpA[5]); // Add square(11)
   res[11] = r2;
   r3      = _mm256_add_epi64(r3, r3);                    // Double(12)
   r3      = _mm256_madd52lo_epu64(r3, inpA[6], inpA[6]); // Add square(12)
   res[12] = r3;
   r4      = _mm256_add_epi64(r4, r4);                    // Double(13)
   r4      = _mm256_madd52hi_epu64(r4, inpA[6], inpA[6]); // Add square(13)
   res[13] = r4;
   r5      = _mm256_add_epi64(r5, r5);                    // Double(14)
   r5      = _mm256_madd52lo_epu64(r5, inpA[7], inpA[7]); // Add square(14)
   res[14] = r5;
   r6      = _mm256_add_epi64(r6, r6);                    // Double(15)
   r6      = _mm256_madd52hi_epu64(r6, inpA[7], inpA[7]); // Add square(15)
   res[15] = r6;
   r7      = _mm256_add_epi64(r7, r7);                    // Double(16)
   r7      = _mm256_madd52lo_epu64(r7, inpA[8], inpA[8]); // Add square(16)
   res[16] = r7;
   r0      = r8;
   r1      = zero_simd;
   r2      = zero_simd;
   r3      = zero_simd;
   AL      = inpA[0];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[17]); // Sum(17)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[18]); // Sum(18)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[19]); // Sum(19)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[17]); // Sum(17)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[18]); // Sum(18)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[19]); // Sum(19)
   AL      = inpA[1];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[16]); // Sum(17)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[17]); // Sum(18)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[18]); // Sum(19)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[16]); // Sum(17)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[17]); // Sum(18)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[18]); // Sum(19)
   AL      = inpA[2];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[15]); // Sum(17)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[16]); // Sum(18)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[17]); // Sum(19)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[15]); // Sum(17)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[16]); // Sum(18)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[17]); // Sum(19)
   AL      = inpA[3];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[14]); // Sum(17)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[15]); // Sum(18)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[16]); // Sum(19)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[14]); // Sum(17)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[15]); // Sum(18)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[16]); // Sum(19)
   AL      = inpA[4];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[13]); // Sum(17)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[14]); // Sum(18)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[15]); // Sum(19)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[13]); // Sum(17)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[14]); // Sum(18)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[15]); // Sum(19)
   AL      = inpA[5];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[12]); // Sum(17)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[13]); // Sum(18)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[14]); // Sum(19)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[12]); // Sum(17)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[13]); // Sum(18)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[14]); // Sum(19)
   AL      = inpA[6];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[11]); // Sum(17)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[12]); // Sum(18)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[13]); // Sum(19)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[11]); // Sum(17)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[12]); // Sum(18)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[13]); // Sum(19)
   AL      = inpA[7];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[10]); // Sum(17)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[11]); // Sum(18)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[12]); // Sum(19)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[10]); // Sum(17)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[11]); // Sum(18)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[12]); // Sum(19)
   AL      = inpA[8];
   r0      = _mm256_madd52lo_epu64(r0, AL, inpA[9]);  // Sum(17)
   r1      = _mm256_madd52lo_epu64(r1, AL, inpA[10]); // Sum(18)
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[11]); // Sum(19)
   r1      = _mm256_madd52hi_epu64(r1, AL, inpA[9]);  // Sum(17)
   r2      = _mm256_madd52hi_epu64(r2, AL, inpA[10]); // Sum(18)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[11]); // Sum(19)
   AL      = inpA[9];
   r2      = _mm256_madd52lo_epu64(r2, AL, inpA[10]); // Sum(19)
   r3      = _mm256_madd52hi_epu64(r3, AL, inpA[10]); // Sum(19)
   AL      = inpA[10];
   AL      = inpA[11];
   r0      = _mm256_add_epi64(r0, r0);                    // Double(17)
   r0      = _mm256_madd52hi_epu64(r0, inpA[8], inpA[8]); // Add square(17)
   res[17] = r0;
   r1      = _mm256_add_epi64(r1, r1);                    // Double(18)
   r1      = _mm256_madd52lo_epu64(r1, inpA[9], inpA[9]); // Add square(18)
   res[18] = r1;
   r2      = _mm256_add_epi64(r2, r2);                    // Double(19)
   r2      = _mm256_madd52hi_epu64(r2, inpA[9], inpA[9]); // Add square(19)
   res[19] = r2;
   r0      = r3;
   res[20] = r0; // finish up 1st triangle

   ASM("jmp l0\nl0:\n");

   // 2nd triangle - sum the products, double and square
   r1          = zero_simd;
   r2          = zero_simd;
   r3          = zero_simd;
   r4          = zero_simd;
   r5          = zero_simd;
   r6          = zero_simd;
   r7          = zero_simd;
   r8          = zero_simd;
   AL          = inpA[19];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[1]); // Sum(21)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[2]); // Sum(22)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[3]); // Sum(23)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[4]); // Sum(24)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[5]); // Sum(25)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[6]); // Sum(26)
   r6          = _mm256_madd52lo_epu64(r6, AL, inpA[7]); // Sum(27)
   r7          = _mm256_madd52lo_epu64(r7, AL, inpA[8]); // Sum(28)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[1]); // Sum(21)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[2]); // Sum(22)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[3]); // Sum(23)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[4]); // Sum(24)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[5]); // Sum(25)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[6]); // Sum(26)
   r7          = _mm256_madd52hi_epu64(r7, AL, inpA[7]); // Sum(27)
   r8          = _mm256_madd52hi_epu64(r8, AL, inpA[8]); // Sum(28)
   AL          = inpA[18];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[2]); // Sum(21)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[3]); // Sum(22)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[4]); // Sum(23)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[5]); // Sum(24)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[6]); // Sum(25)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[7]); // Sum(26)
   r6          = _mm256_madd52lo_epu64(r6, AL, inpA[8]); // Sum(27)
   r7          = _mm256_madd52lo_epu64(r7, AL, inpA[9]); // Sum(28)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[2]); // Sum(21)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[3]); // Sum(22)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[4]); // Sum(23)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[5]); // Sum(24)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[6]); // Sum(25)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[7]); // Sum(26)
   r7          = _mm256_madd52hi_epu64(r7, AL, inpA[8]); // Sum(27)
   r8          = _mm256_madd52hi_epu64(r8, AL, inpA[9]); // Sum(28)
   AL          = inpA[17];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[3]);  // Sum(21)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[4]);  // Sum(22)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[5]);  // Sum(23)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[6]);  // Sum(24)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[7]);  // Sum(25)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[8]);  // Sum(26)
   r6          = _mm256_madd52lo_epu64(r6, AL, inpA[9]);  // Sum(27)
   r7          = _mm256_madd52lo_epu64(r7, AL, inpA[10]); // Sum(28)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[3]);  // Sum(21)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[4]);  // Sum(22)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[5]);  // Sum(23)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[6]);  // Sum(24)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[7]);  // Sum(25)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[8]);  // Sum(26)
   r7          = _mm256_madd52hi_epu64(r7, AL, inpA[9]);  // Sum(27)
   r8          = _mm256_madd52hi_epu64(r8, AL, inpA[10]); // Sum(28)
   AL          = inpA[16];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[4]);  // Sum(21)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[5]);  // Sum(22)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[6]);  // Sum(23)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[7]);  // Sum(24)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[8]);  // Sum(25)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[9]);  // Sum(26)
   r6          = _mm256_madd52lo_epu64(r6, AL, inpA[10]); // Sum(27)
   r7          = _mm256_madd52lo_epu64(r7, AL, inpA[11]); // Sum(28)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[4]);  // Sum(21)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[5]);  // Sum(22)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[6]);  // Sum(23)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[7]);  // Sum(24)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[8]);  // Sum(25)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[9]);  // Sum(26)
   r7          = _mm256_madd52hi_epu64(r7, AL, inpA[10]); // Sum(27)
   r8          = _mm256_madd52hi_epu64(r8, AL, inpA[11]); // Sum(28)
   AL          = inpA[15];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[5]);  // Sum(21)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[6]);  // Sum(22)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[7]);  // Sum(23)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[8]);  // Sum(24)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[9]);  // Sum(25)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[10]); // Sum(26)
   r6          = _mm256_madd52lo_epu64(r6, AL, inpA[11]); // Sum(27)
   r7          = _mm256_madd52lo_epu64(r7, AL, inpA[12]); // Sum(28)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[5]);  // Sum(21)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[6]);  // Sum(22)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[7]);  // Sum(23)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[8]);  // Sum(24)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[9]);  // Sum(25)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[10]); // Sum(26)
   r7          = _mm256_madd52hi_epu64(r7, AL, inpA[11]); // Sum(27)
   r8          = _mm256_madd52hi_epu64(r8, AL, inpA[12]); // Sum(28)
   AL          = inpA[14];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[6]);  // Sum(21)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[7]);  // Sum(22)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[8]);  // Sum(23)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[9]);  // Sum(24)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[10]); // Sum(25)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[11]); // Sum(26)
   r6          = _mm256_madd52lo_epu64(r6, AL, inpA[12]); // Sum(27)
   r7          = _mm256_madd52lo_epu64(r7, AL, inpA[13]); // Sum(28)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[6]);  // Sum(21)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[7]);  // Sum(22)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[8]);  // Sum(23)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[9]);  // Sum(24)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[10]); // Sum(25)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[11]); // Sum(26)
   r7          = _mm256_madd52hi_epu64(r7, AL, inpA[12]); // Sum(27)
   r8          = _mm256_madd52hi_epu64(r8, AL, inpA[13]); // Sum(28)
   AL          = inpA[13];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[7]);  // Sum(21)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[8]);  // Sum(22)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[9]);  // Sum(23)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[10]); // Sum(24)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[11]); // Sum(25)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[12]); // Sum(26)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[7]);  // Sum(21)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[8]);  // Sum(22)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[9]);  // Sum(23)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[10]); // Sum(24)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[11]); // Sum(25)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[12]); // Sum(26)
   AL          = inpA[12];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[8]);  // Sum(21)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[9]);  // Sum(22)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[10]); // Sum(23)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[11]); // Sum(24)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[8]);  // Sum(21)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[9]);  // Sum(22)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[10]); // Sum(23)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[11]); // Sum(24)
   AL          = inpA[11];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[9]);        // Sum(21)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[10]);       // Sum(22)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[9]);        // Sum(21)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[10]);       // Sum(22)
   r0          = _mm256_add_epi64(r0, r0);                      // Double(20)
   r0          = _mm256_madd52lo_epu64(r0, inpA[10], inpA[10]); // Add square(20)
   res[N + 0]  = r0;
   r1          = _mm256_add_epi64(r1, r1);                      // Double(21)
   r1          = _mm256_madd52hi_epu64(r1, inpA[10], inpA[10]); // Add square(21)
   res[N + 1]  = r1;
   r2          = _mm256_add_epi64(r2, r2);                      // Double(22)
   r2          = _mm256_madd52lo_epu64(r2, inpA[11], inpA[11]); // Add square(22)
   res[N + 2]  = r2;
   r3          = _mm256_add_epi64(r3, r3);                      // Double(23)
   r3          = _mm256_madd52hi_epu64(r3, inpA[11], inpA[11]); // Add square(23)
   res[N + 3]  = r3;
   r4          = _mm256_add_epi64(r4, r4);                      // Double(24)
   r4          = _mm256_madd52lo_epu64(r4, inpA[12], inpA[12]); // Add square(24)
   res[N + 4]  = r4;
   r5          = _mm256_add_epi64(r5, r5);                      // Double(25)
   r5          = _mm256_madd52hi_epu64(r5, inpA[12], inpA[12]); // Add square(25)
   res[N + 5]  = r5;
   r6          = _mm256_add_epi64(r6, r6);                      // Double(26)
   r6          = _mm256_madd52lo_epu64(r6, inpA[13], inpA[13]); // Add square(26)
   res[N + 6]  = r6;
   r7          = _mm256_add_epi64(r7, r7);                      // Double(27)
   r7          = _mm256_madd52hi_epu64(r7, inpA[13], inpA[13]); // Add square(27)
   res[N + 7]  = r7;
   r0          = r8;
   r1          = zero_simd;
   r2          = zero_simd;
   r3          = zero_simd;
   r4          = zero_simd;
   r5          = zero_simd;
   r6          = zero_simd;
   r7          = zero_simd;
   r8          = zero_simd;
   AL          = inpA[19];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[9]);  // Sum(29)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[10]); // Sum(30)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[11]); // Sum(31)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[12]); // Sum(32)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[13]); // Sum(33)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[14]); // Sum(34)
   r6          = _mm256_madd52lo_epu64(r6, AL, inpA[15]); // Sum(35)
   r7          = _mm256_madd52lo_epu64(r7, AL, inpA[16]); // Sum(36)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[9]);  // Sum(29)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[10]); // Sum(30)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[11]); // Sum(31)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[12]); // Sum(32)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[13]); // Sum(33)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[14]); // Sum(34)
   r7          = _mm256_madd52hi_epu64(r7, AL, inpA[15]); // Sum(35)
   r8          = _mm256_madd52hi_epu64(r8, AL, inpA[16]); // Sum(36)
   AL          = inpA[18];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[10]); // Sum(29)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[11]); // Sum(30)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[12]); // Sum(31)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[13]); // Sum(32)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[14]); // Sum(33)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[15]); // Sum(34)
   r6          = _mm256_madd52lo_epu64(r6, AL, inpA[16]); // Sum(35)
   r7          = _mm256_madd52lo_epu64(r7, AL, inpA[17]); // Sum(36)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[10]); // Sum(29)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[11]); // Sum(30)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[12]); // Sum(31)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[13]); // Sum(32)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[14]); // Sum(33)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[15]); // Sum(34)
   r7          = _mm256_madd52hi_epu64(r7, AL, inpA[16]); // Sum(35)
   r8          = _mm256_madd52hi_epu64(r8, AL, inpA[17]); // Sum(36)
   AL          = inpA[17];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[11]); // Sum(29)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[12]); // Sum(30)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[13]); // Sum(31)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[14]); // Sum(32)
   r4          = _mm256_madd52lo_epu64(r4, AL, inpA[15]); // Sum(33)
   r5          = _mm256_madd52lo_epu64(r5, AL, inpA[16]); // Sum(34)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[11]); // Sum(29)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[12]); // Sum(30)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[13]); // Sum(31)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[14]); // Sum(32)
   r5          = _mm256_madd52hi_epu64(r5, AL, inpA[15]); // Sum(33)
   r6          = _mm256_madd52hi_epu64(r6, AL, inpA[16]); // Sum(34)
   AL          = inpA[16];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[12]); // Sum(29)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[13]); // Sum(30)
   r2          = _mm256_madd52lo_epu64(r2, AL, inpA[14]); // Sum(31)
   r3          = _mm256_madd52lo_epu64(r3, AL, inpA[15]); // Sum(32)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[12]); // Sum(29)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[13]); // Sum(30)
   r3          = _mm256_madd52hi_epu64(r3, AL, inpA[14]); // Sum(31)
   r4          = _mm256_madd52hi_epu64(r4, AL, inpA[15]); // Sum(32)
   AL          = inpA[15];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[13]);       // Sum(29)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[14]);       // Sum(30)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[13]);       // Sum(29)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[14]);       // Sum(30)
   r0          = _mm256_add_epi64(r0, r0);                      // Double(28)
   r0          = _mm256_madd52lo_epu64(r0, inpA[14], inpA[14]); // Add square(28)
   res[N + 8]  = r0;
   r1          = _mm256_add_epi64(r1, r1);                      // Double(29)
   r1          = _mm256_madd52hi_epu64(r1, inpA[14], inpA[14]); // Add square(29)
   res[N + 9]  = r1;
   r2          = _mm256_add_epi64(r2, r2);                      // Double(30)
   r2          = _mm256_madd52lo_epu64(r2, inpA[15], inpA[15]); // Add square(30)
   res[N + 10] = r2;
   r3          = _mm256_add_epi64(r3, r3);                      // Double(31)
   r3          = _mm256_madd52hi_epu64(r3, inpA[15], inpA[15]); // Add square(31)
   res[N + 11] = r3;
   r4          = _mm256_add_epi64(r4, r4);                      // Double(32)
   r4          = _mm256_madd52lo_epu64(r4, inpA[16], inpA[16]); // Add square(32)
   res[N + 12] = r4;
   r5          = _mm256_add_epi64(r5, r5);                      // Double(33)
   r5          = _mm256_madd52hi_epu64(r5, inpA[16], inpA[16]); // Add square(33)
   res[N + 13] = r5;
   r6          = _mm256_add_epi64(r6, r6);                      // Double(34)
   r6          = _mm256_madd52lo_epu64(r6, inpA[17], inpA[17]); // Add square(34)
   res[N + 14] = r6;
   r7          = _mm256_add_epi64(r7, r7);                      // Double(35)
   r7          = _mm256_madd52hi_epu64(r7, inpA[17], inpA[17]); // Add square(35)
   res[N + 15] = r7;
   r0          = r8;
   r1          = zero_simd;
   r2          = zero_simd;
   r3          = zero_simd;
   AL          = inpA[19];
   r0          = _mm256_madd52lo_epu64(r0, AL, inpA[17]);       // Sum(37)
   r1          = _mm256_madd52lo_epu64(r1, AL, inpA[18]);       // Sum(38)
   r1          = _mm256_madd52hi_epu64(r1, AL, inpA[17]);       // Sum(37)
   r2          = _mm256_madd52hi_epu64(r2, AL, inpA[18]);       // Sum(38)
   r0          = _mm256_add_epi64(r0, r0);                      // Double(36)
   r0          = _mm256_madd52lo_epu64(r0, inpA[18], inpA[18]); // Add square(36)
   res[N + 16] = r0;
   r1          = _mm256_add_epi64(r1, r1);                      // Double(37)
   r1          = _mm256_madd52hi_epu64(r1, inpA[18], inpA[18]); // Add square(37)
   res[N + 17] = r1;
   r2          = _mm256_add_epi64(r2, r2);                      // Double(38)
   r2          = _mm256_madd52lo_epu64(r2, inpA[19], inpA[19]); // Add square(38)
   res[N + 18] = r2;
   r0          = r3;
   // finish up doubling
   res[N + 19] = _mm256_madd52hi_epu64(zero_simd, inpA[19], inpA[19]);
}

void AMS52x20_diagonal_mb4(int64u *out_mb, const int64u *inpA_mb, const int64u *inpM_mb, const int64u *k0_mb)
{
   const int N = 20;
   __m256i res[20 * 2];

   /* Square only */
   ams52x20_square_diagonal_mb4(res, inpA_mb);

   /* Generate u_i and begin reduction */
   ams_reduce_52xN_mb4(res, inpM_mb, k0_mb, N);

   /* Normalize */
   ifma_normalize_ams_52xN_mb4(out_mb, res, N);
}

#endif // #if ((_MBX == _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
