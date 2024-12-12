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

#ifndef AVXIFMA_AMM_H
#define AVXIFMA_AMM_H

#include <internal/common/ifma_math.h>
#include <internal/rsa/ifma_rsa_arith.h>
#include <crypto_mb/defs.h>
#include <assert.h>

/*
Almost Montgomery Multiplication

Output:
    out_mb   : C = A*B*(2^(-N*52)) mod M
Inputs:
    inpA_mb  : A (N*52-bit input)
    inpB_mb  : B (N*52-bit input)
    inpM_mb  : M (N*52-bit modulus)
    k0_mb    : mu, montgomery constant = (-M^(-1) mod 2^(52))
    N        : size of the operation (number of 52-bit words)
               i.e. N=20 corresponds to 1024-bit operation

    C=0
    for i from 0 to N - 1:
        C=C+A*B[i]
        T=C[0]*mu	// discard T[1]
        C=C+T[0]*M	// C[0] is zero
        C=C>>52		// at each step of the for loop, divide the result by 2^52
    return C
*/
__MBX_INLINE void ifma_amm52xN_mb4(int64u* out_mb,
                                   const int64u* inpA_mb,
                                   const int64u* inpB_mb,
                                   const int64u* inpM_mb,
                                   const int64u* k0_mb,
                                   const int N)
{
    const __m256i* inpA = (const __m256i*)inpA_mb;
    const __m256i* inpB = (const __m256i*)inpB_mb;
    const __m256i* inpM = (const __m256i*)inpM_mb;
    const __m256i K0    = _mm256_load_si256((const __m256i*)&k0_mb[0]);
    __m256i C[79];
    int i;

    assert(N <= 79);
    zero_mb4(C, N);

    for (i = 0; i < N; i++) {
        const register __m256i Bi = inpB[i];
        register __m256i r0, r1, r2, r3, r4, r5, r6, r7;
        int j;

        /* calculate C[0] and prepare T */
        r0 = _mm256_madd52lo_epu64(C[0], Bi, inpA[0]);

        const register __m256i T = _mm256_madd52lo_epu64(_mm256_setzero_si256(), r0, K0);

        r1 = _mm256_madd52lo_epu64(C[1], Bi, inpA[1]);

        r0 = _mm256_madd52lo_epu64(r0, T, inpM[0]);
        r1 = _mm256_madd52lo_epu64(r1, T, inpM[1]);

        r0 = _mm256_srli_epi64(r0, DIGIT_SIZE);
        r1 = _mm256_add_epi64(r1, r0);

        r0   = _mm256_madd52hi_epu64(r1, Bi, inpA[0]);
        r0   = _mm256_madd52hi_epu64(r0, T, inpM[0]);
        C[0] = r0;

        // calculate C[2, 3, ..., N-2]
        for (j = 2; (j + 8) < N; j += 8) {
            // This loop calculates 8 C[] values to keep number of independent IFMA operations running
            r0 = C[j + 0];
            r1 = C[j + 1];
            r2 = C[j + 2];
            r3 = C[j + 3];
            r4 = C[j + 4];
            r5 = C[j + 5];
            r6 = C[j + 6];
            r7 = C[j + 7];

            r0 = _mm256_madd52lo_epu64(r0, Bi, inpA[j + 0]);
            r1 = _mm256_madd52lo_epu64(r1, Bi, inpA[j + 1]);
            r2 = _mm256_madd52lo_epu64(r2, Bi, inpA[j + 2]);
            r3 = _mm256_madd52lo_epu64(r3, Bi, inpA[j + 3]);
            r4 = _mm256_madd52lo_epu64(r4, Bi, inpA[j + 4]);
            r5 = _mm256_madd52lo_epu64(r5, Bi, inpA[j + 5]);
            r6 = _mm256_madd52lo_epu64(r6, Bi, inpA[j + 6]);
            r7 = _mm256_madd52lo_epu64(r7, Bi, inpA[j + 7]);

            r0 = _mm256_madd52lo_epu64(r0, T, inpM[j + 0]);
            r1 = _mm256_madd52lo_epu64(r1, T, inpM[j + 1]);
            r2 = _mm256_madd52lo_epu64(r2, T, inpM[j + 2]);
            r3 = _mm256_madd52lo_epu64(r3, T, inpM[j + 3]);
            r4 = _mm256_madd52lo_epu64(r4, T, inpM[j + 4]);
            r5 = _mm256_madd52lo_epu64(r5, T, inpM[j + 5]);
            r6 = _mm256_madd52lo_epu64(r6, T, inpM[j + 6]);
            r7 = _mm256_madd52lo_epu64(r7, T, inpM[j + 7]);

            r0 = _mm256_madd52hi_epu64(r0, Bi, inpA[j + 0 - 1]);
            r1 = _mm256_madd52hi_epu64(r1, Bi, inpA[j + 1 - 1]);
            r2 = _mm256_madd52hi_epu64(r2, Bi, inpA[j + 2 - 1]);
            r3 = _mm256_madd52hi_epu64(r3, Bi, inpA[j + 3 - 1]);
            r4 = _mm256_madd52hi_epu64(r4, Bi, inpA[j + 4 - 1]);
            r5 = _mm256_madd52hi_epu64(r5, Bi, inpA[j + 5 - 1]);
            r6 = _mm256_madd52hi_epu64(r6, Bi, inpA[j + 6 - 1]);
            r7 = _mm256_madd52hi_epu64(r7, Bi, inpA[j + 7 - 1]);

            r0 = _mm256_madd52hi_epu64(r0, T, inpM[j + 0 - 1]);
            r1 = _mm256_madd52hi_epu64(r1, T, inpM[j + 1 - 1]);
            r2 = _mm256_madd52hi_epu64(r2, T, inpM[j + 2 - 1]);
            r3 = _mm256_madd52hi_epu64(r3, T, inpM[j + 3 - 1]);
            r4 = _mm256_madd52hi_epu64(r4, T, inpM[j + 4 - 1]);
            r5 = _mm256_madd52hi_epu64(r5, T, inpM[j + 5 - 1]);
            r6 = _mm256_madd52hi_epu64(r6, T, inpM[j + 6 - 1]);
            r7 = _mm256_madd52hi_epu64(r7, T, inpM[j + 7 - 1]);

            C[j + 0 - 1] = r0;
            C[j + 1 - 1] = r1;
            C[j + 2 - 1] = r2;
            C[j + 3 - 1] = r3;
            C[j + 4 - 1] = r4;
            C[j + 5 - 1] = r5;
            C[j + 6 - 1] = r6;
            C[j + 7 - 1] = r7;
        }

        // finish up remaining computations in 4's and 1's
        for (; (j + 4) < N; j += 4) {
            r0 = C[j + 0];
            r1 = C[j + 1];
            r2 = C[j + 2];
            r3 = C[j + 3];

            r0 = _mm256_madd52lo_epu64(r0, Bi, inpA[j + 0]);
            r1 = _mm256_madd52lo_epu64(r1, Bi, inpA[j + 1]);
            r2 = _mm256_madd52lo_epu64(r2, Bi, inpA[j + 2]);
            r3 = _mm256_madd52lo_epu64(r3, Bi, inpA[j + 3]);

            r0 = _mm256_madd52lo_epu64(r0, T, inpM[j + 0]);
            r1 = _mm256_madd52lo_epu64(r1, T, inpM[j + 1]);
            r2 = _mm256_madd52lo_epu64(r2, T, inpM[j + 2]);
            r3 = _mm256_madd52lo_epu64(r3, T, inpM[j + 3]);

            r0 = _mm256_madd52hi_epu64(r0, Bi, inpA[j + 0 - 1]);
            r1 = _mm256_madd52hi_epu64(r1, Bi, inpA[j + 1 - 1]);
            r2 = _mm256_madd52hi_epu64(r2, Bi, inpA[j + 2 - 1]);
            r3 = _mm256_madd52hi_epu64(r3, Bi, inpA[j + 3 - 1]);

            r0 = _mm256_madd52hi_epu64(r0, T, inpM[j + 0 - 1]);
            r1 = _mm256_madd52hi_epu64(r1, T, inpM[j + 1 - 1]);
            r2 = _mm256_madd52hi_epu64(r2, T, inpM[j + 2 - 1]);
            r3 = _mm256_madd52hi_epu64(r3, T, inpM[j + 3 - 1]);

            C[j + 0 - 1] = r0;
            C[j + 1 - 1] = r1;
            C[j + 2 - 1] = r2;
            C[j + 3 - 1] = r3;
        }

        for (; j < N; j++) {
            r0       = C[j];
            r0       = _mm256_madd52lo_epu64(r0, Bi, inpA[j]);
            r0       = _mm256_madd52lo_epu64(r0, T, inpM[j]);
            r0       = _mm256_madd52hi_epu64(r0, Bi, inpA[j - 1]);
            r0       = _mm256_madd52hi_epu64(r0, T, inpM[j - 1]);
            C[j - 1] = r0;
        }

        /* finish up with the last element */
        r0       = _mm256_madd52hi_epu64(_mm256_setzero_si256(), Bi, inpA[N - 1]);
        r0       = _mm256_madd52hi_epu64(r0, T, inpM[N - 1]);
        C[N - 1] = r0;
    }

    /* Normalization and return C */
    ifma_normalize_clear_52xN_mb4(out_mb, C, N);
}

#endif /* AVXIFMA_AMM_H */
