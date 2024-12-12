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

#ifndef AVXIFMA_AHMR_H
#define AVXIFMA_AHMR_H

#include <assert.h>
#include <internal/common/ifma_math.h>
#include <internal/rsa/ifma_rsa_arith.h>

/*
Almost Half Montgomery Reduction (AHMR)

Output:
    out_mb   : C = A*(2^(-10*52)) mod M
Inputs:
    inpA_mb  : A (N*52-bit input)
    inpM_mb  : M (N*52-bit modulus)
    k0_mb    : montgomery constant = (-M^(-1) mod 2^(52))
    N        : size of the operation (number of 52-bit words)
               i.e. N=20 corresponds to 1024-bit operation

    C=A
    for i from 0 to N/2 - 1:
        T=C[0]*mu	// discard T[1]
        C=C+T[0]*M	// C[0] is zero
        C=C>>52		// at each step of the for loop, divide the result by 2^52
    return C
*/

__MBX_INLINE void ifma_ahmr52xN_mb4(int64u* out_mb,
                                    const int64u* inpA_mb,
                                    const int64u* inpM_mb,
                                    const int64u* k0_mb,
                                    const int N)
{
    const __m256i* inpM = (const __m256i*)inpM_mb;
    const __m256i* inpA = (const __m256i*)inpA_mb;
    __m256i C[40];
    int i;

    const __m256i MASK52 = _mm256_set1_epi64x(DIGIT_MASK);

    assert(N <= 40);

    // C=A
    for (i = 0; i < N; i++)
        C[i] = _mm256_and_si256(inpA[i], MASK52);

    const __m256i mont_constant = _mm256_loadu_si256((const __m256i*)&k0_mb[0]);

    for (i = 0; i < (N / 2); i++) {
        // T=C[0]*mu
        const __m256i T = _mm256_madd52lo_epu64(_mm256_setzero_si256(), C[0], mont_constant);

        // C=C+T[0]*M (low part)
        C[0] = _mm256_madd52lo_epu64(C[0], T, inpM[0]);

        // low 52 (DIGIT_SIZE) bits of C[0] are 0
        // high 12 bits are accumulated to C[1] (same bit-weight)
        C[1] = _mm256_add_epi64(C[1], _mm256_srli_epi64(C[0], DIGIT_SIZE));

        int j;

        for (j = 0; j < (N - 1); j++) {
            /* C[j] = C[j + 1] + LO(T x M[j + 1]) + HI(T x M[j]) */
            const __m256i L = _mm256_madd52lo_epu64(C[j + 1], T, inpM[j + 1]);

            C[j] = _mm256_madd52hi_epu64(L, T, inpM[j]);
        }

        // C[N-1]
        C[j] = _mm256_madd52hi_epu64(_mm256_setzero_si256(), T, inpM[j]);
    }

    // return C
    ifma_normalize_52xN_mb4(out_mb, C, N);
}

#endif /* AVXIFMA_AHMR_H */
