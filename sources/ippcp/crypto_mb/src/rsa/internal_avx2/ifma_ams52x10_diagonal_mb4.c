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

static void ams52x10_square_diagonal_mb4(__m256i* res, const int64u* inpA_mb)
{
    const __m256i* inpA = (const __m256i*)inpA_mb;
    register __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8, AL;
    const int N             = 10;
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
    r0      = _mm256_madd52lo_epu64(r0, AL, inpA[1]);      // Sum(1)
    r1      = _mm256_madd52lo_epu64(r1, AL, inpA[2]);      // Sum(2)
    r2      = _mm256_madd52lo_epu64(r2, AL, inpA[3]);      // Sum(3)
    r3      = _mm256_madd52lo_epu64(r3, AL, inpA[4]);      // Sum(4)
    r4      = _mm256_madd52lo_epu64(r4, AL, inpA[5]);      // Sum(5)
    r5      = _mm256_madd52lo_epu64(r5, AL, inpA[6]);      // Sum(6)
    r6      = _mm256_madd52lo_epu64(r6, AL, inpA[7]);      // Sum(7)
    r7      = _mm256_madd52lo_epu64(r7, AL, inpA[8]);      // Sum(8)
    r1      = _mm256_madd52hi_epu64(r1, AL, inpA[1]);      // Sum(1)
    r2      = _mm256_madd52hi_epu64(r2, AL, inpA[2]);      // Sum(2)
    r3      = _mm256_madd52hi_epu64(r3, AL, inpA[3]);      // Sum(3)
    r4      = _mm256_madd52hi_epu64(r4, AL, inpA[4]);      // Sum(4)
    r5      = _mm256_madd52hi_epu64(r5, AL, inpA[5]);      // Sum(5)
    r6      = _mm256_madd52hi_epu64(r6, AL, inpA[6]);      // Sum(6)
    r7      = _mm256_madd52hi_epu64(r7, AL, inpA[7]);      // Sum(7)
    r8      = _mm256_madd52hi_epu64(r8, AL, inpA[8]);      // Sum(8)
    AL      = inpA[1];
    r2      = _mm256_madd52lo_epu64(r2, AL, inpA[2]);      // Sum(3)
    r3      = _mm256_madd52lo_epu64(r3, AL, inpA[3]);      // Sum(4)
    r4      = _mm256_madd52lo_epu64(r4, AL, inpA[4]);      // Sum(5)
    r5      = _mm256_madd52lo_epu64(r5, AL, inpA[5]);      // Sum(6)
    r6      = _mm256_madd52lo_epu64(r6, AL, inpA[6]);      // Sum(7)
    r7      = _mm256_madd52lo_epu64(r7, AL, inpA[7]);      // Sum(8)
    r3      = _mm256_madd52hi_epu64(r3, AL, inpA[2]);      // Sum(3)
    r4      = _mm256_madd52hi_epu64(r4, AL, inpA[3]);      // Sum(4)
    r5      = _mm256_madd52hi_epu64(r5, AL, inpA[4]);      // Sum(5)
    r6      = _mm256_madd52hi_epu64(r6, AL, inpA[5]);      // Sum(6)
    r7      = _mm256_madd52hi_epu64(r7, AL, inpA[6]);      // Sum(7)
    r8      = _mm256_madd52hi_epu64(r8, AL, inpA[7]);      // Sum(8)
    AL      = inpA[2];
    r4      = _mm256_madd52lo_epu64(r4, AL, inpA[3]);      // Sum(5)
    r5      = _mm256_madd52lo_epu64(r5, AL, inpA[4]);      // Sum(6)
    r6      = _mm256_madd52lo_epu64(r6, AL, inpA[5]);      // Sum(7)
    r7      = _mm256_madd52lo_epu64(r7, AL, inpA[6]);      // Sum(8)
    r5      = _mm256_madd52hi_epu64(r5, AL, inpA[3]);      // Sum(5)
    r6      = _mm256_madd52hi_epu64(r6, AL, inpA[4]);      // Sum(6)
    r7      = _mm256_madd52hi_epu64(r7, AL, inpA[5]);      // Sum(7)
    r8      = _mm256_madd52hi_epu64(r8, AL, inpA[6]);      // Sum(8)
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
    AL      = inpA[0];
    r0      = _mm256_madd52lo_epu64(r0, AL, inpA[9]); // Sum(9)
    r1      = _mm256_madd52hi_epu64(r1, AL, inpA[9]); // Sum(9)
    AL      = inpA[1];
    r0      = _mm256_madd52lo_epu64(r0, AL, inpA[8]); // Sum(9)
    r1      = _mm256_madd52hi_epu64(r1, AL, inpA[8]); // Sum(9)
    AL      = inpA[2];
    r0      = _mm256_madd52lo_epu64(r0, AL, inpA[7]); // Sum(9)
    r1      = _mm256_madd52hi_epu64(r1, AL, inpA[7]); // Sum(9)
    AL      = inpA[3];
    r0      = _mm256_madd52lo_epu64(r0, AL, inpA[6]); // Sum(9)
    r1      = _mm256_madd52hi_epu64(r1, AL, inpA[6]); // Sum(9)
    AL      = inpA[4];
    r0      = _mm256_madd52lo_epu64(r0, AL, inpA[5]); // Sum(9)
    r1      = _mm256_madd52hi_epu64(r1, AL, inpA[5]); // Sum(9)
    AL      = inpA[5];
    AL      = inpA[6];
    AL      = inpA[7];
    r0      = _mm256_add_epi64(r0, r0);                    // Double(9)
    r0      = _mm256_madd52hi_epu64(r0, inpA[4], inpA[4]); // Add square(9)
    res[9]  = r0;
    r0      = r1;
    res[10] = r0;                                          // finish up 1st triangle

    ASM("jmp l0\nl0:\n");

    // 2nd triangle - sum the products, double and square
    r1         = zero_simd;
    r2         = zero_simd;
    r3         = zero_simd;
    r4         = zero_simd;
    r5         = zero_simd;
    r6         = zero_simd;
    r7         = zero_simd;
    r8         = zero_simd;
    AL         = inpA[9];
    r0         = _mm256_madd52lo_epu64(r0, AL, inpA[1]);      // Sum(11)
    r1         = _mm256_madd52lo_epu64(r1, AL, inpA[2]);      // Sum(12)
    r2         = _mm256_madd52lo_epu64(r2, AL, inpA[3]);      // Sum(13)
    r3         = _mm256_madd52lo_epu64(r3, AL, inpA[4]);      // Sum(14)
    r4         = _mm256_madd52lo_epu64(r4, AL, inpA[5]);      // Sum(15)
    r5         = _mm256_madd52lo_epu64(r5, AL, inpA[6]);      // Sum(16)
    r6         = _mm256_madd52lo_epu64(r6, AL, inpA[7]);      // Sum(17)
    r7         = _mm256_madd52lo_epu64(r7, AL, inpA[8]);      // Sum(18)
    r1         = _mm256_madd52hi_epu64(r1, AL, inpA[1]);      // Sum(11)
    r2         = _mm256_madd52hi_epu64(r2, AL, inpA[2]);      // Sum(12)
    r3         = _mm256_madd52hi_epu64(r3, AL, inpA[3]);      // Sum(13)
    r4         = _mm256_madd52hi_epu64(r4, AL, inpA[4]);      // Sum(14)
    r5         = _mm256_madd52hi_epu64(r5, AL, inpA[5]);      // Sum(15)
    r6         = _mm256_madd52hi_epu64(r6, AL, inpA[6]);      // Sum(16)
    r7         = _mm256_madd52hi_epu64(r7, AL, inpA[7]);      // Sum(17)
    r8         = _mm256_madd52hi_epu64(r8, AL, inpA[8]);      // Sum(18)
    AL         = inpA[8];
    r0         = _mm256_madd52lo_epu64(r0, AL, inpA[2]);      // Sum(11)
    r1         = _mm256_madd52lo_epu64(r1, AL, inpA[3]);      // Sum(12)
    r2         = _mm256_madd52lo_epu64(r2, AL, inpA[4]);      // Sum(13)
    r3         = _mm256_madd52lo_epu64(r3, AL, inpA[5]);      // Sum(14)
    r4         = _mm256_madd52lo_epu64(r4, AL, inpA[6]);      // Sum(15)
    r5         = _mm256_madd52lo_epu64(r5, AL, inpA[7]);      // Sum(16)
    r1         = _mm256_madd52hi_epu64(r1, AL, inpA[2]);      // Sum(11)
    r2         = _mm256_madd52hi_epu64(r2, AL, inpA[3]);      // Sum(12)
    r3         = _mm256_madd52hi_epu64(r3, AL, inpA[4]);      // Sum(13)
    r4         = _mm256_madd52hi_epu64(r4, AL, inpA[5]);      // Sum(14)
    r5         = _mm256_madd52hi_epu64(r5, AL, inpA[6]);      // Sum(15)
    r6         = _mm256_madd52hi_epu64(r6, AL, inpA[7]);      // Sum(16)
    AL         = inpA[7];
    r0         = _mm256_madd52lo_epu64(r0, AL, inpA[3]);      // Sum(11)
    r1         = _mm256_madd52lo_epu64(r1, AL, inpA[4]);      // Sum(12)
    r2         = _mm256_madd52lo_epu64(r2, AL, inpA[5]);      // Sum(13)
    r3         = _mm256_madd52lo_epu64(r3, AL, inpA[6]);      // Sum(14)
    r1         = _mm256_madd52hi_epu64(r1, AL, inpA[3]);      // Sum(11)
    r2         = _mm256_madd52hi_epu64(r2, AL, inpA[4]);      // Sum(12)
    r3         = _mm256_madd52hi_epu64(r3, AL, inpA[5]);      // Sum(13)
    r4         = _mm256_madd52hi_epu64(r4, AL, inpA[6]);      // Sum(14)
    AL         = inpA[6];
    r0         = _mm256_madd52lo_epu64(r0, AL, inpA[4]);      // Sum(11)
    r1         = _mm256_madd52lo_epu64(r1, AL, inpA[5]);      // Sum(12)
    r1         = _mm256_madd52hi_epu64(r1, AL, inpA[4]);      // Sum(11)
    r2         = _mm256_madd52hi_epu64(r2, AL, inpA[5]);      // Sum(12)
    r0         = _mm256_add_epi64(r0, r0);                    // Double(10)
    r0         = _mm256_madd52lo_epu64(r0, inpA[5], inpA[5]); // Add square(10)
    res[N + 0] = r0;
    r1         = _mm256_add_epi64(r1, r1);                    // Double(11)
    r1         = _mm256_madd52hi_epu64(r1, inpA[5], inpA[5]); // Add square(11)
    res[N + 1] = r1;
    r2         = _mm256_add_epi64(r2, r2);                    // Double(12)
    r2         = _mm256_madd52lo_epu64(r2, inpA[6], inpA[6]); // Add square(12)
    res[N + 2] = r2;
    r3         = _mm256_add_epi64(r3, r3);                    // Double(13)
    r3         = _mm256_madd52hi_epu64(r3, inpA[6], inpA[6]); // Add square(13)
    res[N + 3] = r3;
    r4         = _mm256_add_epi64(r4, r4);                    // Double(14)
    r4         = _mm256_madd52lo_epu64(r4, inpA[7], inpA[7]); // Add square(14)
    res[N + 4] = r4;
    r5         = _mm256_add_epi64(r5, r5);                    // Double(15)
    r5         = _mm256_madd52hi_epu64(r5, inpA[7], inpA[7]); // Add square(15)
    res[N + 5] = r5;
    r6         = _mm256_add_epi64(r6, r6);                    // Double(16)
    r6         = _mm256_madd52lo_epu64(r6, inpA[8], inpA[8]); // Add square(16)
    res[N + 6] = r6;
    r7         = _mm256_add_epi64(r7, r7);                    // Double(17)
    r7         = _mm256_madd52hi_epu64(r7, inpA[8], inpA[8]); // Add square(17)
    res[N + 7] = r7;
    r0         = r8;
    r1         = zero_simd;
    r0         = _mm256_add_epi64(r0, r0);                    // Double(18)
    r0         = _mm256_madd52lo_epu64(r0, inpA[9], inpA[9]); // Add square(18)
    res[N + 8] = r0;
    r0         = r1;
    // finish up doubling
    res[N + 9] = _mm256_madd52hi_epu64(zero_simd, inpA[9], inpA[9]);
}

void AMS52x10_diagonal_mb4(int64u* out_mb,
                           const int64u* inpA_mb,
                           const int64u* inpM_mb,
                           const int64u* k0_mb)
{
    const int N = 10;
    __m256i res[10 * 2];

    /* Square only */
    ams52x10_square_diagonal_mb4(res, inpA_mb);

    /* Generate u_i and begin reduction */
    ams_reduce_52xN_mb4(res, inpM_mb, k0_mb, N);

    /* Normalize */
    ifma_normalize_ams_52xN_mb4(out_mb, res, N);
}

#endif // #if ((_MBX == _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
