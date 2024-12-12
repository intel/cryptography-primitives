/*************************************************************************
* Copyright (C) 2022 Intel Corporation
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

#include <internal/sm4/sm4_gcm_mb.h>

#if (_MBX >= _MBX_K1)

/*
// This function precomputes haskeys for delayed reduction:
// hashkeys >> 1 mod poly and hashkeys ^ 2 >> 1 mod poly ... hashkeys ^ 7 >> 1 mod poly
//
// This code is a port of GCM part of Intel(R) IPSec AES-GCM code
// Code modified to work with multi-buffer approach
*/

void sm4_gcm_precompute_hashkey_mb16(const mbx_sm4_key_schedule* key_sched,
                                     SM4_GCM_CTX_mb16* p_context)
{
    const __m512i* p_rk = (const __m512i*)key_sched;
    __m512i tmp;

    /* Encrypt zero blocks */
    __m512i hashkey_blocks_4_0 = setzero();
    __m512i hashkey_blocks_4_1 = setzero();
    __m512i hashkey_blocks_4_2 = setzero();
    __m512i hashkey_blocks_4_3 = setzero();

    for (int itr = 0; itr < SM4_ROUNDS; itr += 4, p_rk += 4) {
        SM4_FOUR_ROUNDS(hashkey_blocks_4_0,
                        hashkey_blocks_4_1,
                        hashkey_blocks_4_2,
                        hashkey_blocks_4_3,
                        tmp,
                        p_rk,
                        1);
    }

    tmp                = hashkey_blocks_4_0;
    hashkey_blocks_4_0 = hashkey_blocks_4_3;
    hashkey_blocks_4_3 = tmp;
    tmp                = hashkey_blocks_4_1;
    hashkey_blocks_4_1 = hashkey_blocks_4_2;
    hashkey_blocks_4_2 = tmp;

    /* Get the right endianness */
    __m512i T1_0 = unpacklo_epi32(hashkey_blocks_4_0, hashkey_blocks_4_1);
    __m512i T1_1 = unpackhi_epi32(hashkey_blocks_4_0, hashkey_blocks_4_1);
    __m512i T1_2 = unpacklo_epi32(hashkey_blocks_4_2, hashkey_blocks_4_3);
    __m512i T1_3 = unpackhi_epi32(hashkey_blocks_4_2, hashkey_blocks_4_3);

    hashkey_blocks_4_0 = unpacklo_epi64(T1_0, T1_2);
    hashkey_blocks_4_1 = unpackhi_epi64(T1_0, T1_2);
    hashkey_blocks_4_2 = unpacklo_epi64(T1_1, T1_3);
    hashkey_blocks_4_3 = unpackhi_epi64(T1_1, T1_3);

    hashkey_blocks_4_0 = shuffle_epi8(hashkey_blocks_4_0, M512(swapWordsOrder));
    hashkey_blocks_4_1 = shuffle_epi8(hashkey_blocks_4_1, M512(swapWordsOrder));
    hashkey_blocks_4_2 = shuffle_epi8(hashkey_blocks_4_2, M512(swapWordsOrder));
    hashkey_blocks_4_3 = shuffle_epi8(hashkey_blocks_4_3, M512(swapWordsOrder));

    /* compute hashkeys >> 1 mod poly */
    T1_0               = srli_epi64(hashkey_blocks_4_0, 63);
    T1_1               = srli_epi64(hashkey_blocks_4_1, 63);
    T1_2               = srli_epi64(hashkey_blocks_4_2, 63);
    T1_3               = srli_epi64(hashkey_blocks_4_3, 63);
    hashkey_blocks_4_0 = slli_epi64(hashkey_blocks_4_0, 1);
    hashkey_blocks_4_1 = slli_epi64(hashkey_blocks_4_1, 1);
    hashkey_blocks_4_2 = slli_epi64(hashkey_blocks_4_2, 1);
    hashkey_blocks_4_3 = slli_epi64(hashkey_blocks_4_3, 1);

    __m512i T2_0 = bsrli_epi128(T1_0, 8);
    __m512i T2_1 = bsrli_epi128(T1_1, 8);
    __m512i T2_2 = bsrli_epi128(T1_2, 8);
    __m512i T2_3 = bsrli_epi128(T1_3, 8);
    T1_0         = bslli_epi128(T1_0, 8);
    T1_1         = bslli_epi128(T1_1, 8);
    T1_2         = bslli_epi128(T1_2, 8);
    T1_3         = bslli_epi128(T1_3, 8);

    hashkey_blocks_4_0 = or (hashkey_blocks_4_0, T1_0);
    hashkey_blocks_4_1 = or (hashkey_blocks_4_1, T1_1);
    hashkey_blocks_4_2 = or (hashkey_blocks_4_2, T1_2);
    hashkey_blocks_4_3 = or (hashkey_blocks_4_3, T1_3);

    T1_0 = shuffle_epi32(T2_0, 0b00100100);
    T1_1 = shuffle_epi32(T2_1, 0b00100100);
    T1_2 = shuffle_epi32(T2_2, 0b00100100);
    T1_3 = shuffle_epi32(T2_3, 0b00100100);

    __mmask16 cmp_mask_0 = cmpeq_epi32_mask(T1_0, M512(two_one));
    __mmask16 cmp_mask_1 = cmpeq_epi32_mask(T1_1, M512(two_one));
    __mmask16 cmp_mask_2 = cmpeq_epi32_mask(T1_2, M512(two_one));
    __mmask16 cmp_mask_3 = cmpeq_epi32_mask(T1_3, M512(two_one));
    T1_0                 = mask_set1_epi32(T1_0, cmp_mask_0, 0xFFFFFFFF);
    T1_1                 = mask_set1_epi32(T1_1, cmp_mask_1, 0xFFFFFFFF);
    T1_2                 = mask_set1_epi32(T1_2, cmp_mask_2, 0xFFFFFFFF);
    T1_3                 = mask_set1_epi32(T1_3, cmp_mask_3, 0xFFFFFFFF);

    T1_0               = and(T1_0, M512(gcm_poly));
    T1_1               = and(T1_1, M512(gcm_poly));
    T1_2               = and(T1_2, M512(gcm_poly));
    T1_3               = and(T1_3, M512(gcm_poly));
    hashkey_blocks_4_0 = xor(hashkey_blocks_4_0, T1_0);
    hashkey_blocks_4_1 = xor(hashkey_blocks_4_1, T1_1);
    hashkey_blocks_4_2 = xor(hashkey_blocks_4_2, T1_2);
    hashkey_blocks_4_3 = xor(hashkey_blocks_4_3, T1_3);

    __m128i* p_hashkey = (__m128i*)SM4_GCM_CONTEXT_HASHKEY(p_context)[0];

    storeu(p_hashkey + 0, hashkey_blocks_4_0);
    storeu(p_hashkey + 4, hashkey_blocks_4_1);
    storeu(p_hashkey + 8, hashkey_blocks_4_2);
    storeu(p_hashkey + 12, hashkey_blocks_4_3);

    /* compute hashkeys ^ 2 >> 1 mod poly ... hashkeys ^ 7 >> 1 mod poly */
    __m512i hashkey_pwr_blocks_4_0 = hashkey_blocks_4_0;
    __m512i hashkey_pwr_blocks_4_1 = hashkey_blocks_4_1;
    __m512i hashkey_pwr_blocks_4_2 = hashkey_blocks_4_2;
    __m512i hashkey_pwr_blocks_4_3 = hashkey_blocks_4_3;

    __m512i* hashkey[] = {
        &hashkey_blocks_4_0, &hashkey_blocks_4_1, &hashkey_blocks_4_2, &hashkey_blocks_4_3
    };
    __m512i* hashkey_pwr[] = { &hashkey_pwr_blocks_4_0,
                               &hashkey_pwr_blocks_4_1,
                               &hashkey_pwr_blocks_4_2,
                               &hashkey_pwr_blocks_4_3 };

    for (int i = 1; i < 8; i++) {
        sm4_gcm_ghash_mul_single_block_mb16(hashkey_pwr, hashkey);

        p_hashkey = (__m128i*)SM4_GCM_CONTEXT_HASHKEY(p_context)[i];

        storeu(p_hashkey + 0, hashkey_pwr_blocks_4_0);
        storeu(p_hashkey + 4, hashkey_pwr_blocks_4_1);
        storeu(p_hashkey + 8, hashkey_pwr_blocks_4_2);
        storeu(p_hashkey + 12, hashkey_pwr_blocks_4_3);
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
