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

#ifndef AVXIFMA_AHMM_H
#define AVXIFMA_AHMM_H

#include <internal/rsa/ifma_rsa_arith.h>
#include <assert.h>
#include <internal/common/ifma_math.h>

/*
Almost Half Montgomery Multiplication (AHMM)

Output:
    out_mb   : C = A*B*(2^(-N*52)) mod M
Inputs:
    inpA_mb  : A (N*52-bit input)
    inpB_mb  : B (N*52-bit input)
    inpBx_mb : K = B*(2^(-(N/2)*52)) mod M
    inpM_mb  : M (N*52-bit modulus)
    k0_mb    : montgomery constant = (-M^(-1) mod 2^(52))
    N        : size of the operation (number of 52-bit words)
               i.e. N=20 corresponds to 1024-bit operation

    AL=A[(N/2) - 1 :   0]
    AH=A[    N - 1 : N/2]

    C=0
    for i from 0 to N/2-1:
        C=C+AL[i]*K+AH[i]*B
        T=C[0]*mu	// discard T[1]
        C=C+T[0]*M	// C[0] is zero
        C=C>>52		// at each step of the for loop, divide the result by 2^52
    return C
*/

__MBX_INLINE void ifma_ahmm52xN_mb4(int64u* out_mb,
                                    const int64u* inpA_mb,
                                    const int64u* inpB_mb,
                                    const int64u* inpBx_mb,
                                    const int64u* inpM_mb,
                                    const int64u* k0_mb,
                                    const int N)
{
    const __m256i* A     = (const __m256i*)inpA_mb;
    const __m256i* mulb  = (const __m256i*)inpB_mb;
    const __m256i* mulbx = (const __m256i*)inpBx_mb;
    const __m256i* M     = (const __m256i*)inpM_mb;

    // Temporary Registers to hold 20 52-bit intermediate results
    int i;

    // C = 0
    __m256i C[40 + 1];

    assert(N <= 40);
    zero_mb4(C, N + 1);

    // Precomputed Montgomery constant (-M^(-1) mod 2^(52))
    const __m256i mont_constant = _mm256_loadu_si256((const __m256i*)k0_mb);

    for (i = 0; i < (N / 2); i++) {
        //******************************************************
        // The loop realizes the following operations
        //   C=C+AL[i]*K+AH[i]*B
        //   T=C[0]*mu
        //   C=C+T[0]*M
        //   C=C>>52
        //******************************************************

        // load AH[i]
        const __m256i AH = A[i + (N / 2)];

        // load AL[i]
        const __m256i AL = A[i];

        int j;

        // C[0] and C[1] computation is unrolled to compute T[0] and
        // get 8xC[] value computation loop going

        // C=C+AH[i]*B
        C[0] = _mm256_madd52lo_epu64(C[0], AH, mulb[0]);

        // C=C+AL[i]*K (low part)
        C[0] = _mm256_madd52lo_epu64(C[0], AL, mulbx[0]);

        // T=C[0]*mu
        const __m256i T = _mm256_madd52lo_epu64(_mm256_setzero_si256(), C[0], mont_constant);

        // C=C+T[0]*M (low part)
        C[0] = _mm256_madd52lo_epu64(C[0], T, M[0]);

        // C[1]
        // C=C+AH[i]*B
        C[1] = _mm256_madd52hi_epu64(C[1], AH, mulb[0]);
        C[1] = _mm256_madd52lo_epu64(C[1], AH, mulb[1]);

        // C=C+AL[i]*K (low part)
        C[1] = _mm256_madd52hi_epu64(C[1], AL, mulbx[0]);
        C[1] = _mm256_madd52lo_epu64(C[1], AL, mulbx[1]);

        // low 52 (DIGIT_SIZE) bits of C[0] are 0
        // high 12 bits are accumulated to C[1] (same bit-weight)
        C[1] = _mm256_add_epi64(C[1], _mm256_srli_epi64(C[0], DIGIT_SIZE));

        const __m256i L0 = _mm256_madd52hi_epu64(C[1], T, M[0]);
        C[0]             = _mm256_madd52lo_epu64(L0, T, M[1]);

        for (j = 2; (j + 7) < N; j += 8) {
            // This loop works on 8 result words at the same time C[j], C[j+1], ... C[j+7].
            // This is to keep 8 independent IFMA operations in flight.
            register __m256i r0 = C[j + 0], r1 = C[j + 1], r2 = C[j + 2], r3 = C[j + 3],
                             r4 = C[j + 4], r5 = C[j + 5], r6 = C[j + 6], r7 = C[j + 7];

            // C=C+AH[i]*B
            r0 = _mm256_madd52hi_epu64(r0, AH, mulb[j - 1]);
            r1 = _mm256_madd52hi_epu64(r1, AH, mulb[j + 0]);
            r2 = _mm256_madd52hi_epu64(r2, AH, mulb[j + 1]);
            r3 = _mm256_madd52hi_epu64(r3, AH, mulb[j + 2]);
            r4 = _mm256_madd52hi_epu64(r4, AH, mulb[j + 3]);
            r5 = _mm256_madd52hi_epu64(r5, AH, mulb[j + 4]);
            r6 = _mm256_madd52hi_epu64(r6, AH, mulb[j + 5]);
            r7 = _mm256_madd52hi_epu64(r7, AH, mulb[j + 6]);

            r0 = _mm256_madd52lo_epu64(r0, AH, mulb[j + 0]);
            r1 = _mm256_madd52lo_epu64(r1, AH, mulb[j + 1]);
            r2 = _mm256_madd52lo_epu64(r2, AH, mulb[j + 2]);
            r3 = _mm256_madd52lo_epu64(r3, AH, mulb[j + 3]);
            r4 = _mm256_madd52lo_epu64(r4, AH, mulb[j + 4]);
            r5 = _mm256_madd52lo_epu64(r5, AH, mulb[j + 5]);
            r6 = _mm256_madd52lo_epu64(r6, AH, mulb[j + 6]);
            r7 = _mm256_madd52lo_epu64(r7, AH, mulb[j + 7]);

            // C=C+AL[i]*K (low part)
            r0 = _mm256_madd52hi_epu64(r0, AL, mulbx[j - 1]);
            r1 = _mm256_madd52hi_epu64(r1, AL, mulbx[j + 0]);
            r2 = _mm256_madd52hi_epu64(r2, AL, mulbx[j + 1]);
            r3 = _mm256_madd52hi_epu64(r3, AL, mulbx[j + 2]);
            r4 = _mm256_madd52hi_epu64(r4, AL, mulbx[j + 3]);
            r5 = _mm256_madd52hi_epu64(r5, AL, mulbx[j + 4]);
            r6 = _mm256_madd52hi_epu64(r6, AL, mulbx[j + 5]);
            r7 = _mm256_madd52hi_epu64(r7, AL, mulbx[j + 6]);

            r0 = _mm256_madd52lo_epu64(r0, AL, mulbx[j + 0]);
            r1 = _mm256_madd52lo_epu64(r1, AL, mulbx[j + 1]);
            r2 = _mm256_madd52lo_epu64(r2, AL, mulbx[j + 2]);
            r3 = _mm256_madd52lo_epu64(r3, AL, mulbx[j + 3]);
            r4 = _mm256_madd52lo_epu64(r4, AL, mulbx[j + 4]);
            r5 = _mm256_madd52lo_epu64(r5, AL, mulbx[j + 5]);
            r6 = _mm256_madd52lo_epu64(r6, AL, mulbx[j + 6]);
            r7 = _mm256_madd52lo_epu64(r7, AL, mulbx[j + 7]);

            /* C[j] = C[j + 1] + LO(T x M[j + 1]) + HI(T x M[j]) */
            r0 = _mm256_madd52hi_epu64(r0, T, M[j - 1]);
            r1 = _mm256_madd52hi_epu64(r1, T, M[j + 0]);
            r2 = _mm256_madd52hi_epu64(r2, T, M[j + 1]);
            r3 = _mm256_madd52hi_epu64(r3, T, M[j + 2]);
            r4 = _mm256_madd52hi_epu64(r4, T, M[j + 3]);
            r5 = _mm256_madd52hi_epu64(r5, T, M[j + 4]);
            r6 = _mm256_madd52hi_epu64(r6, T, M[j + 5]);
            r7 = _mm256_madd52hi_epu64(r7, T, M[j + 6]);

            r0 = _mm256_madd52lo_epu64(r0, T, M[j + 0]);
            r1 = _mm256_madd52lo_epu64(r1, T, M[j + 1]);
            r2 = _mm256_madd52lo_epu64(r2, T, M[j + 2]);
            r3 = _mm256_madd52lo_epu64(r3, T, M[j + 3]);
            r4 = _mm256_madd52lo_epu64(r4, T, M[j + 4]);
            r5 = _mm256_madd52lo_epu64(r5, T, M[j + 5]);
            r6 = _mm256_madd52lo_epu64(r6, T, M[j + 6]);
            r7 = _mm256_madd52lo_epu64(r7, T, M[j + 7]);

            C[j - 1] = r0;
            C[j + 0] = r1;
            C[j + 1] = r2;
            C[j + 2] = r3;
            C[j + 3] = r4;
            C[j + 4] = r5;
            C[j + 5] = r6;
            C[j + 6] = r7;
        }

        for (; j < N; j++) {
            // Finish up by computing 1 result per loop.
            register __m256i r0 = C[j + 0];

            // C=C+AH[i]*B
            r0 = _mm256_madd52hi_epu64(r0, AH, mulb[j - 1]);
            r0 = _mm256_madd52lo_epu64(r0, AH, mulb[j + 0]);

            // C=C+AL[i]*K (low part)
            r0 = _mm256_madd52hi_epu64(r0, AL, mulbx[j - 1]);
            r0 = _mm256_madd52lo_epu64(r0, AL, mulbx[j + 0]);

            /* C[j] = C[j + 1] + LO(T x M[j + 1]) + HI(T x M[j]) */
            r0 = _mm256_madd52hi_epu64(r0, T, M[j - 1]);
            r0 = _mm256_madd52lo_epu64(r0, T, M[j + 0]);

            C[j - 1] = r0;
        }

        // C[N] = HI(AH[i] x B) + HI(AL[i] x K)
        C[j] = _mm256_madd52hi_epu64(_mm256_setzero_si256(), AH, mulb[j - 1]);
        C[j] = _mm256_madd52hi_epu64(C[j], AL, mulbx[j - 1]);

        // C[N-1] = C[N] + HI(T x M[N - 1]) */
        j    = N - 1;
        C[j] = _mm256_madd52hi_epu64(C[j + 1], T, M[j]);

        //******************************************************
    }

    /* Normalization - without clearing the top bits */
    ifma_normalize_52xN_mb4(out_mb, C, N);
}

#endif /* AVXIFMA_AHMM_H */
