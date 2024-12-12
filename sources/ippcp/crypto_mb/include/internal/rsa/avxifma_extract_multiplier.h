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

#ifndef AVXIFMA_EXTRACT_MULTIPLIER_H
#define AVXIFMA_EXTRACT_MULTIPLIER_H

#include <internal/common/ifma_math.h>

/*
Constant time extraction of multipliers from the lookup table for 4 independent operations

Output:
    pOut       :
Inputs:
    pTbl       : two dimensional table [2^exp_window_size][MB4 * N*52-bit]
    idx_target : SIMD word with 4 64-bit indexes to pTbl[]
    N          : size of the operation (number of 52-bit data words packed in 64-bit words)
                 i.e. N=20 corresponds to 1024-bit operation stored in 20*64-bits
    exp_window_size : exponentiation window size

    L=2^exp_window_size

    // assume multiplier from index 0 is required
    pOut[0..N-1] = pTbl[0][0..N-1]

    for i from 1 to L-1:
        K = (i == idx_target) ? 0xffffffff_ffffffff : 0
        pOut[0..N-1] = (pOut[0..N-1] & (~K)) | (pTbl[i][0..L-1] & K)

 */
__MBX_INLINE void extract_multiplier_mb4_N(__m256i* pOut,
                                           const __m256i* pTbl,
                                           const __m256i idx_target,
                                           const int N,
                                           const int exp_window_size)
{
    // Assume first element is what we need
    int i;

    for (i = 0; i < N; i++)
        pOut[i] = *pTbl++;

    // Find out what we actually need or just keep the original
    for (i = 1; i < (1 << exp_window_size); i++) {
        const __m256i idx_curr = _mm256_set1_epi64x(i);
        const __m256i k        = _mm256_cmpeq_epi64(idx_curr, idx_target);

        for (int j = 0; j < N; j++) {
            const __m256i temp = *pTbl++;

            pOut[j] = _mm256_or_si256(_mm256_and_si256(k, temp), _mm256_andnot_si256(k, pOut[j]));
        }
    }
}

__MBX_INLINE void extract_1x_mb4(__m256i* mulB,
                                 const __m256i* pMulTbl,
                                 const __m256i k,
                                 const __m256i idx_target,
                                 const int N)
{
    int i;

    for (i = 0; i < N; i++) {
        const __m256i temp = _mm256_stream_load_si256(&pMulTbl[i]);

        mulB[i] = _mm256_or_si256(_mm256_and_si256(k, temp), _mm256_andnot_si256(k, mulB[i]));
    }
}

__MBX_INLINE void extract_mb4(__m256i* pMulb,
                              const __m256i* pMulTbl,
                              const int iter,
                              const __m256i idx_target,
                              const int N)
{
    int j;

    for (j = 0; j < 4; j++) {
        const int l            = j + (4 * iter);
        const __m256i idx_curr = _mm256_set1_epi64x(l);
        const __m256i k        = _mm256_cmpeq_epi64(idx_curr, idx_target);

        extract_1x_mb4(&pMulb[0], &pMulTbl[0], k, idx_target, N);

        pMulTbl += N;
    }
}

#endif /* AVXIFMA_EXTRACT_MULTIPLIER_H */
