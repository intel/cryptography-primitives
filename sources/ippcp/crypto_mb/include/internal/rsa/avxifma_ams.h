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

#ifndef AVXIFMA_AMS_H
#define AVXIFMA_AMS_H

#include <internal/rsa/ifma_rsa_arith.h>
#include <crypto_mb/defs.h>
#include <internal/common/ifma_math.h>
#include <assert.h>

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

/*
Montgomery reduction after squaring

Output (N*52-bits):
    res      : C = A*(2^(-10*52)) mod M
Inputs:
    res      : A (2*N*52-bit input)
    inpM_mb  : M (N*52-bit modulus)
    k0_mb    : montgomery constant = (-M^(-1) mod 2^(52))
    N        : size of the operation (number of 52-bit words)
               i.e. N=20 corresponds to 1024-bit operation

    // Note: implemented as an in-place operation (res = A, and C = res)
    C=A

    for i from 0 to N - 1:
        u=C[0]*mu	// discard u[1]
        C=C+u[0]*M	// C[0] is zero
        C=C>>52		// at each step of the for loop, divide the result by 2^52
    return C
*/
__MBX_INLINE void ams_reduce_52xN_mb4(__m256i* res,
                                      const int64u* inpM_mb,
                                      const int64u* k0_mb,
                                      const int N)
{
    /* Generate u_i */
    const __m256i K0    = _mm256_load_si256((const __m256i*)&k0_mb[0]);
    const __m256i* inpM = (const __m256i*)inpM_mb;
    int i;

    for (i = 0; i < N; i++) {
        register __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8;
        int j = 0;

        r0 = res[i]; /* res[i + j + 0] and j=0 here */

        if (i != 0)
            r0 = _mm256_add_epi64(r0, _mm256_srli_epi64(res[i - 1], DIGIT_SIZE));

        const __m256i u = _mm256_madd52lo_epu64(_mm256_setzero_si256(), r0, K0);

        for (; (j + 8) < N; j += 8) {
            // keep 8 independent IFMA operations in flight
            r1 = res[i + j + 1];
            r2 = res[i + j + 2];
            r3 = res[i + j + 3];
            r4 = res[i + j + 4];
            r5 = res[i + j + 5];
            r6 = res[i + j + 6];
            r7 = res[i + j + 7];
            r8 = res[i + j + 8];

            r0 = _mm256_madd52lo_epu64(r0, u, inpM[j + 0]);
            r1 = _mm256_madd52lo_epu64(r1, u, inpM[j + 1]);
            r2 = _mm256_madd52lo_epu64(r2, u, inpM[j + 2]);
            r3 = _mm256_madd52lo_epu64(r3, u, inpM[j + 3]);
            r4 = _mm256_madd52lo_epu64(r4, u, inpM[j + 4]);
            r5 = _mm256_madd52lo_epu64(r5, u, inpM[j + 5]);
            r6 = _mm256_madd52lo_epu64(r6, u, inpM[j + 6]);
            r7 = _mm256_madd52lo_epu64(r7, u, inpM[j + 7]);

            r1 = _mm256_madd52hi_epu64(r1, u, inpM[j + 0]);
            r2 = _mm256_madd52hi_epu64(r2, u, inpM[j + 1]);
            r3 = _mm256_madd52hi_epu64(r3, u, inpM[j + 2]);
            r4 = _mm256_madd52hi_epu64(r4, u, inpM[j + 3]);
            r5 = _mm256_madd52hi_epu64(r5, u, inpM[j + 4]);
            r6 = _mm256_madd52hi_epu64(r6, u, inpM[j + 5]);
            r7 = _mm256_madd52hi_epu64(r7, u, inpM[j + 6]);
            r8 = _mm256_madd52hi_epu64(r8, u, inpM[j + 7]);

            res[i + j + 0] = r0;
            res[i + j + 1] = r1;
            res[i + j + 2] = r2;
            res[i + j + 3] = r3;
            res[i + j + 4] = r4;
            res[i + j + 5] = r5;
            res[i + j + 6] = r6;
            res[i + j + 7] = r7;
            r0             = r8;
        }

        for (; (j + 4) < N; j += 4) {
            // keep 4 independent IFMA operations in flight
            r1 = res[i + j + 1];
            r2 = res[i + j + 2];
            r3 = res[i + j + 3];
            r4 = res[i + j + 4];

            r0 = _mm256_madd52lo_epu64(r0, u, inpM[j + 0]);
            r1 = _mm256_madd52lo_epu64(r1, u, inpM[j + 1]);
            r2 = _mm256_madd52lo_epu64(r2, u, inpM[j + 2]);
            r3 = _mm256_madd52lo_epu64(r3, u, inpM[j + 3]);

            r1 = _mm256_madd52hi_epu64(r1, u, inpM[j + 0]);
            r2 = _mm256_madd52hi_epu64(r2, u, inpM[j + 1]);
            r3 = _mm256_madd52hi_epu64(r3, u, inpM[j + 2]);
            r4 = _mm256_madd52hi_epu64(r4, u, inpM[j + 3]);

            res[i + j + 0] = r0;
            res[i + j + 1] = r1;
            res[i + j + 2] = r2;
            res[i + j + 3] = r3;
            r0             = r4;
        }

        // finish up computation with reduction at a time
        for (; j < N; j++) {
            r1         = res[i + j + 1];
            r0         = _mm256_madd52lo_epu64(r0, u, inpM[j]);
            r1         = _mm256_madd52hi_epu64(r1, u, inpM[j]);
            res[i + j] = r0;
            r0         = r1;
        }

        res[i + j] = r0;
    }
}

/*
Square operation

Output (2*N*52-bits):
    res      : C = A*A
Inputs:
    inpA     : A (N*52-bit input)
    N        : size of the operation (number of 52-bit words)
               i.e. N=20 corresponds to 1024-bit operation

    C = 0 // note: assumed to be done outside this function

    // triangle
    for i from 0 to N-2:
        AL = A[i]
        for j from i+1 to N-1:
            C[i+j] = C[i+j] + AL*A[j]

    // double
    for i from 0 to 2*N-1:
        C[i] = 2*C[i]

    // add square diagonal
    for i from 0 to N-1:
        C[i*2] = C[i*2] + A[i]*A[i]

    return C
*/
__MBX_INLINE void ams52xN_square_diagonal_mb4(__m256i* res, const __m256i* inpA, const int N)
{
    /* Sum */
    for (int i = 0; i < (N - 1); i++) {
        const __m256i AL = inpA[i];

        for (int j = i + 1; j < N; j++) {
            const __m256i AR = inpA[j];
            const int iL     = i + j;
            const int iH     = iL + 1;

            res[iL] = _mm256_madd52lo_epu64(res[iL], AL, AR);
            res[iH] = _mm256_madd52hi_epu64(res[iH], AL, AR);
        }
    }

    /* Double */
    for (int i = 0; i < (N * 2); i++)
        res[i] = _mm256_add_epi64(res[i], res[i]);

    /* Add square */
    for (int i = 0; i < N; i++) {
        const __m256i AL = inpA[i];
        const int iL     = 2 * i;
        const int iH     = iL + 1;

        res[iL] = _mm256_madd52lo_epu64(res[iL], AL, AL);
        res[iH] = _mm256_madd52hi_epu64(res[iH], AL, AL);
    }
}

/*
Almost Montgomery Square

NOTE: This function is just for reference.
      All optimized AMS code use auto-generated square functions and
      only leverage reduction & normalization functions from this module

Output (N*52-bits):
    out_mb   : C = (A^2)*(2^(-10*52)) mod M
Inputs:
    inpA_mb  : A (N*52-bit input)
    inpM_mb  : M (N*52-bit modulus)
    k0_mb    : montgomery constant = (-M^(-1) mod 2^(52))
    N        : size of the operation (number of 52-bit words)
               i.e. N=20 corresponds to 1024-bit operation

    // square operation expects res to be 0
    // res is 2*N*52 bits in size
    res = 0

    // square A
    res = A^2;

    // reduce
    res[N..2*N-1] = reduce(res[0..2*N-1])

    // normalize and return
    normalize(res[N..2*N-1]
    return res[N..2*N-1]
*/
__MBX_INLINE void AMS52xN_diagonal_mb4(int64u* out_mb,
                                       const int64u* inpA_mb,
                                       const int64u* inpM_mb,
                                       const int64u* k0_mb,
                                       const int N)
{
    __m256i res[79 * 2];

    assert(N <= 79);
    zero_mb4(res, 2 * N);

    /* generic square */
    ams52xN_square_diagonal_mb4(res, (const __m256i*)inpA_mb, N);

    /* Generate u_i and reduce */
    ams_reduce_52xN_mb4(res, inpM_mb, k0_mb, N);

    /* Normalize */
    ifma_normalize_ams_52xN_mb4(out_mb, res, N);
}

#endif /* AVXIFMA_AMS_H */
