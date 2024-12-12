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

#include <internal/common/ifma_defs.h>
#include <internal/sm4/sm4_gcm_mb.h>

#if (_MBX >= _MBX_K1)

__MBX_INLINE void read_first(__m512i* data_blocks[4],
                             const int8u* const pa_input[SM4_LINES],
                             __mmask16 load_mask)
{
    __mmask16 load_mask_0 = load_mask >> 0 * 4;
    __mmask16 load_mask_1 = load_mask >> 1 * 4;
    __mmask16 load_mask_2 = load_mask >> 2 * 4;
    __mmask16 load_mask_3 = load_mask >> 3 * 4;

    *(data_blocks[0]) = setzero();
    *(data_blocks[1]) = setzero();
    *(data_blocks[2]) = setzero();
    *(data_blocks[3]) = setzero();

    /*
   // Loop with 4 iterations here does not unrolled by some compilers
   // Unrolled explicitly because insert32x4 require the last parameter to be const
   */

    /* Begin of explicitly unrolled loop */

    __m128i input_block_0 =
        _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_0), (void*)pa_input[0 + 4 * 0]);
    __m128i input_block_1 =
        _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_1), (void*)pa_input[0 + 4 * 1]);
    __m128i input_block_2 =
        _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_2), (void*)pa_input[0 + 4 * 2]);
    __m128i input_block_3 =
        _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_3), (void*)pa_input[0 + 4 * 3]);

    input_block_0 = _mm_shuffle_epi8(input_block_0, M128(swapEndianness));
    input_block_1 = _mm_shuffle_epi8(input_block_1, M128(swapEndianness));
    input_block_2 = _mm_shuffle_epi8(input_block_2, M128(swapEndianness));
    input_block_3 = _mm_shuffle_epi8(input_block_3, M128(swapEndianness));

    *(data_blocks[0]) = insert32x4(*(data_blocks[0]), input_block_0, 0);
    *(data_blocks[1]) = insert32x4(*(data_blocks[1]), input_block_1, 0);
    *(data_blocks[2]) = insert32x4(*(data_blocks[2]), input_block_2, 0);
    *(data_blocks[3]) = insert32x4(*(data_blocks[3]), input_block_3, 0);

    load_mask_0 >>= 1;
    load_mask_1 >>= 1;
    load_mask_2 >>= 1;
    load_mask_3 >>= 1;

    input_block_0 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_0), (void*)pa_input[1 + 4 * 0]);
    input_block_1 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_1), (void*)pa_input[1 + 4 * 1]);
    input_block_2 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_2), (void*)pa_input[1 + 4 * 2]);
    input_block_3 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_3), (void*)pa_input[1 + 4 * 3]);

    input_block_0 = _mm_shuffle_epi8(input_block_0, M128(swapEndianness));
    input_block_1 = _mm_shuffle_epi8(input_block_1, M128(swapEndianness));
    input_block_2 = _mm_shuffle_epi8(input_block_2, M128(swapEndianness));
    input_block_3 = _mm_shuffle_epi8(input_block_3, M128(swapEndianness));

    *(data_blocks[0]) = insert32x4(*(data_blocks[0]), input_block_0, 1);
    *(data_blocks[1]) = insert32x4(*(data_blocks[1]), input_block_1, 1);
    *(data_blocks[2]) = insert32x4(*(data_blocks[2]), input_block_2, 1);
    *(data_blocks[3]) = insert32x4(*(data_blocks[3]), input_block_3, 1);

    load_mask_0 >>= 1;
    load_mask_1 >>= 1;
    load_mask_2 >>= 1;
    load_mask_3 >>= 1;

    input_block_0 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_0), (void*)pa_input[2 + 4 * 0]);
    input_block_1 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_1), (void*)pa_input[2 + 4 * 1]);
    input_block_2 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_2), (void*)pa_input[2 + 4 * 2]);
    input_block_3 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_3), (void*)pa_input[2 + 4 * 3]);

    input_block_0 = _mm_shuffle_epi8(input_block_0, M128(swapEndianness));
    input_block_1 = _mm_shuffle_epi8(input_block_1, M128(swapEndianness));
    input_block_2 = _mm_shuffle_epi8(input_block_2, M128(swapEndianness));
    input_block_3 = _mm_shuffle_epi8(input_block_3, M128(swapEndianness));

    *(data_blocks[0]) = insert32x4(*(data_blocks[0]), input_block_0, 2);
    *(data_blocks[1]) = insert32x4(*(data_blocks[1]), input_block_1, 2);
    *(data_blocks[2]) = insert32x4(*(data_blocks[2]), input_block_2, 2);
    *(data_blocks[3]) = insert32x4(*(data_blocks[3]), input_block_3, 2);

    load_mask_0 >>= 1;
    load_mask_1 >>= 1;
    load_mask_2 >>= 1;
    load_mask_3 >>= 1;

    input_block_0 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_0), (void*)pa_input[3 + 4 * 0]);
    input_block_1 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_1), (void*)pa_input[3 + 4 * 1]);
    input_block_2 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_2), (void*)pa_input[3 + 4 * 2]);
    input_block_3 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_3), (void*)pa_input[3 + 4 * 3]);

    input_block_0 = _mm_shuffle_epi8(input_block_0, M128(swapEndianness));
    input_block_1 = _mm_shuffle_epi8(input_block_1, M128(swapEndianness));
    input_block_2 = _mm_shuffle_epi8(input_block_2, M128(swapEndianness));
    input_block_3 = _mm_shuffle_epi8(input_block_3, M128(swapEndianness));

    *(data_blocks[0]) = insert32x4(*(data_blocks[0]), input_block_0, 3);
    *(data_blocks[1]) = insert32x4(*(data_blocks[1]), input_block_1, 3);
    *(data_blocks[2]) = insert32x4(*(data_blocks[2]), input_block_2, 3);
    *(data_blocks[3]) = insert32x4(*(data_blocks[3]), input_block_3, 3);

    /* End of explicitly unrolled loop */
}

__MBX_INLINE void read_next(__m512i* data_blocks[4],
                            const int8u* const pa_input[SM4_LINES],
                            int block_number,
                            __mmask16 load_mask)
{
    __mmask16 load_mask_0 = load_mask >> 0 * 4;
    __mmask16 load_mask_1 = load_mask >> 1 * 4;
    __mmask16 load_mask_2 = load_mask >> 2 * 4;
    __mmask16 load_mask_3 = load_mask >> 3 * 4;

    *(data_blocks[0]) = setzero();
    *(data_blocks[1]) = setzero();
    *(data_blocks[2]) = setzero();
    *(data_blocks[3]) = setzero();

    /*
   // Loop with 4 iterations here does not unrolled by some compilers
   // Unrolled explicitly because insert32x4 require the last parameter to be const
   */

    /* Begin of explicitly unrolled loop */

    __m128i input_block_0 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_0),
                                                 (void*)(pa_input[0 + 4 * 0] + block_number * 16));
    __m128i input_block_1 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_1),
                                                 (void*)(pa_input[0 + 4 * 1] + block_number * 16));
    __m128i input_block_2 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_2),
                                                 (void*)(pa_input[0 + 4 * 2] + block_number * 16));
    __m128i input_block_3 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_3),
                                                 (void*)(pa_input[0 + 4 * 3] + block_number * 16));

    input_block_0 = _mm_shuffle_epi8(input_block_0, M128(swapEndianness));
    input_block_1 = _mm_shuffle_epi8(input_block_1, M128(swapEndianness));
    input_block_2 = _mm_shuffle_epi8(input_block_2, M128(swapEndianness));
    input_block_3 = _mm_shuffle_epi8(input_block_3, M128(swapEndianness));

    *(data_blocks[0]) = insert32x4(*(data_blocks[0]), input_block_0, 0);
    *(data_blocks[1]) = insert32x4(*(data_blocks[1]), input_block_1, 0);
    *(data_blocks[2]) = insert32x4(*(data_blocks[2]), input_block_2, 0);
    *(data_blocks[3]) = insert32x4(*(data_blocks[3]), input_block_3, 0);

    load_mask_0 >>= 1;
    load_mask_1 >>= 1;
    load_mask_2 >>= 1;
    load_mask_3 >>= 1;

    input_block_0 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_0),
                                         (void*)(pa_input[1 + 4 * 0] + block_number * 16));
    input_block_1 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_1),
                                         (void*)(pa_input[1 + 4 * 1] + block_number * 16));
    input_block_2 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_2),
                                         (void*)(pa_input[1 + 4 * 2] + block_number * 16));
    input_block_3 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_3),
                                         (void*)(pa_input[1 + 4 * 3] + block_number * 16));

    input_block_0 = _mm_shuffle_epi8(input_block_0, M128(swapEndianness));
    input_block_1 = _mm_shuffle_epi8(input_block_1, M128(swapEndianness));
    input_block_2 = _mm_shuffle_epi8(input_block_2, M128(swapEndianness));
    input_block_3 = _mm_shuffle_epi8(input_block_3, M128(swapEndianness));

    *(data_blocks[0]) = insert32x4(*(data_blocks[0]), input_block_0, 1);
    *(data_blocks[1]) = insert32x4(*(data_blocks[1]), input_block_1, 1);
    *(data_blocks[2]) = insert32x4(*(data_blocks[2]), input_block_2, 1);
    *(data_blocks[3]) = insert32x4(*(data_blocks[3]), input_block_3, 1);

    load_mask_0 >>= 1;
    load_mask_1 >>= 1;
    load_mask_2 >>= 1;
    load_mask_3 >>= 1;

    input_block_0 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_0),
                                         (void*)(pa_input[2 + 4 * 0] + block_number * 16));
    input_block_1 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_1),
                                         (void*)(pa_input[2 + 4 * 1] + block_number * 16));
    input_block_2 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_2),
                                         (void*)(pa_input[2 + 4 * 2] + block_number * 16));
    input_block_3 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_3),
                                         (void*)(pa_input[2 + 4 * 3] + block_number * 16));

    input_block_0 = _mm_shuffle_epi8(input_block_0, M128(swapEndianness));
    input_block_1 = _mm_shuffle_epi8(input_block_1, M128(swapEndianness));
    input_block_2 = _mm_shuffle_epi8(input_block_2, M128(swapEndianness));
    input_block_3 = _mm_shuffle_epi8(input_block_3, M128(swapEndianness));

    *(data_blocks[0]) = insert32x4(*(data_blocks[0]), input_block_0, 2);
    *(data_blocks[1]) = insert32x4(*(data_blocks[1]), input_block_1, 2);
    *(data_blocks[2]) = insert32x4(*(data_blocks[2]), input_block_2, 2);
    *(data_blocks[3]) = insert32x4(*(data_blocks[3]), input_block_3, 2);

    load_mask_0 >>= 1;
    load_mask_1 >>= 1;
    load_mask_2 >>= 1;
    load_mask_3 >>= 1;

    input_block_0 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_0),
                                         (void*)(pa_input[3 + 4 * 0] + block_number * 16));
    input_block_1 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_1),
                                         (void*)(pa_input[3 + 4 * 1] + block_number * 16));
    input_block_2 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_2),
                                         (void*)(pa_input[3 + 4 * 2] + block_number * 16));
    input_block_3 = _mm_maskz_loadu_epi8(0xFFFF * (0x1 & load_mask_3),
                                         (void*)(pa_input[3 + 4 * 3] + block_number * 16));

    input_block_0 = _mm_shuffle_epi8(input_block_0, M128(swapEndianness));
    input_block_1 = _mm_shuffle_epi8(input_block_1, M128(swapEndianness));
    input_block_2 = _mm_shuffle_epi8(input_block_2, M128(swapEndianness));
    input_block_3 = _mm_shuffle_epi8(input_block_3, M128(swapEndianness));

    *(data_blocks[0]) = insert32x4(*(data_blocks[0]), input_block_0, 3);
    *(data_blocks[1]) = insert32x4(*(data_blocks[1]), input_block_1, 3);
    *(data_blocks[2]) = insert32x4(*(data_blocks[2]), input_block_2, 3);
    *(data_blocks[3]) = insert32x4(*(data_blocks[3]), input_block_3, 3);

    /* End of explicitly unrolled loop */
}

/*
// This function updates 16 blocks of ghash by processing full blocks (128 bit blocks) of data
//
// This code is a port of GCM part of Intel(R) IPSec AES-GCM code
// Code modified to work with multi-buffer approach
*/
void sm4_gcm_update_ghash_full_blocks_mb16(__m128i ghash[SM4_LINES],
                                           const int8u* const pa_input[SM4_LINES],
                                           __m512i* input_len,
                                           __m128i hashkey[SM4_GCM_HASHKEY_PWR_NUM][SM4_LINES],
                                           __mmask16 mb_mask)
{

    int stream_len      = 0;
    __mmask16 load_mask = 0;

    __m512i hashkeys_4_0, hashkeys_4_1, hashkeys_4_2, hashkeys_4_3;
    __m512i data_blocks_4_0, data_blocks_4_1, data_blocks_4_2, data_blocks_4_3;
    __m512i* data_blocks[] = {
        &data_blocks_4_0, &data_blocks_4_1, &data_blocks_4_2, &data_blocks_4_3
    };

    __m512i T1_0, T2_0, T3_0, T4_0;
    __m512i T1_1, T2_1, T3_1, T4_1;
    __m512i T1_2, T2_2, T3_2, T4_2;
    __m512i T1_3, T2_3, T3_3, T4_3;

    /* Calculate how many blocks can be processed with delayed reduction */
    for (int i = 8; i > 0; i--) {
        __mmask16 max_stream_len_mask =
            cmp_epi32_mask((*input_len), set1_epi32(16 * i), _MM_CMPINT_GE);
        __mmask16 less_16_mask = cmp_epi32_mask((*input_len), set1_epi32(16), _MM_CMPINT_LT);
        __mmask16 stream_mask  = max_stream_len_mask | less_16_mask;

        load_mask = load_mask * (load_mask != 0) | max_stream_len_mask * (stream_mask == 0xFFFF) *
                                                       (load_mask == 0) * (less_16_mask != 0xFFFF);
        stream_len =
            stream_len + i * (stream_mask == 0xFFFF) * (stream_len == 0) * (less_16_mask != 0xFFFF);
    }

    load_mask &= mb_mask;

    while (load_mask) {

        /* Process first block using hashkey of highest power */

        hashkeys_4_0 = loadu(hashkey[stream_len - 1] + 0);
        hashkeys_4_1 = loadu(hashkey[stream_len - 1] + 4);
        hashkeys_4_2 = loadu(hashkey[stream_len - 1] + 8);
        hashkeys_4_3 = loadu(hashkey[stream_len - 1] + 12);

        read_first(data_blocks, pa_input, load_mask);

        data_blocks_4_0 = xor(data_blocks_4_0, loadu(ghash + 0));
        data_blocks_4_1 = xor(data_blocks_4_1, loadu(ghash + 4));
        data_blocks_4_2 = xor(data_blocks_4_2, loadu(ghash + 8));
        data_blocks_4_3 = xor(data_blocks_4_3, loadu(ghash + 12));

        T1_0 = clmul(hashkeys_4_0, data_blocks_4_0, 0x11);
        T1_1 = clmul(hashkeys_4_1, data_blocks_4_1, 0x11);
        T1_2 = clmul(hashkeys_4_2, data_blocks_4_2, 0x11);
        T1_3 = clmul(hashkeys_4_3, data_blocks_4_3, 0x11);

        T2_0 = clmul(hashkeys_4_0, data_blocks_4_0, 0x00);
        T2_1 = clmul(hashkeys_4_1, data_blocks_4_1, 0x00);
        T2_2 = clmul(hashkeys_4_2, data_blocks_4_2, 0x00);
        T2_3 = clmul(hashkeys_4_3, data_blocks_4_3, 0x00);

        T3_0 = clmul(hashkeys_4_0, data_blocks_4_0, 0x01);
        T3_1 = clmul(hashkeys_4_1, data_blocks_4_1, 0x01);
        T3_2 = clmul(hashkeys_4_2, data_blocks_4_2, 0x01);
        T3_3 = clmul(hashkeys_4_3, data_blocks_4_3, 0x01);

        T4_0 = clmul(hashkeys_4_0, data_blocks_4_0, 0x10);
        T4_1 = clmul(hashkeys_4_1, data_blocks_4_1, 0x10);
        T4_2 = clmul(hashkeys_4_2, data_blocks_4_2, 0x10);
        T4_3 = clmul(hashkeys_4_3, data_blocks_4_3, 0x10);

        T3_0 = xor(T4_0, T3_0);
        T3_1 = xor(T4_1, T3_1);
        T3_2 = xor(T4_2, T3_2);
        T3_3 = xor(T4_3, T3_3);

        /* Process the rest of blocks */
        for (int i = 1; i < stream_len; i++) {

            read_next(data_blocks, pa_input, i, load_mask);

            hashkeys_4_0 = loadu(hashkey[stream_len - i - 1] + 0);
            hashkeys_4_1 = loadu(hashkey[stream_len - i - 1] + 4);
            hashkeys_4_2 = loadu(hashkey[stream_len - i - 1] + 8);
            hashkeys_4_3 = loadu(hashkey[stream_len - i - 1] + 12);

            T4_0 = clmul(hashkeys_4_0, data_blocks_4_0, 0x11);
            T4_1 = clmul(hashkeys_4_1, data_blocks_4_1, 0x11);
            T4_2 = clmul(hashkeys_4_2, data_blocks_4_2, 0x11);
            T4_3 = clmul(hashkeys_4_3, data_blocks_4_3, 0x11);

            T1_0 = xor(T4_0, T1_0);
            T1_1 = xor(T4_1, T1_1);
            T1_2 = xor(T4_2, T1_2);
            T1_3 = xor(T4_3, T1_3);

            T4_0 = clmul(hashkeys_4_0, data_blocks_4_0, 0x00);
            T4_1 = clmul(hashkeys_4_1, data_blocks_4_1, 0x00);
            T4_2 = clmul(hashkeys_4_2, data_blocks_4_2, 0x00);
            T4_3 = clmul(hashkeys_4_3, data_blocks_4_3, 0x00);

            T2_0 = xor(T4_0, T2_0);
            T2_1 = xor(T4_1, T2_1);
            T2_2 = xor(T4_2, T2_2);
            T2_3 = xor(T4_3, T2_3);

            T4_0 = clmul(hashkeys_4_0, data_blocks_4_0, 0x01);
            T4_1 = clmul(hashkeys_4_1, data_blocks_4_1, 0x01);
            T4_2 = clmul(hashkeys_4_2, data_blocks_4_2, 0x01);
            T4_3 = clmul(hashkeys_4_3, data_blocks_4_3, 0x01);

            T3_0 = xor(T4_0, T3_0);
            T3_1 = xor(T4_1, T3_1);
            T3_2 = xor(T4_2, T3_2);
            T3_3 = xor(T4_3, T3_3);

            T4_0 = clmul(hashkeys_4_0, data_blocks_4_0, 0x10);
            T4_1 = clmul(hashkeys_4_1, data_blocks_4_1, 0x10);
            T4_2 = clmul(hashkeys_4_2, data_blocks_4_2, 0x10);
            T4_3 = clmul(hashkeys_4_3, data_blocks_4_3, 0x10);

            T3_0 = xor(T4_0, T3_0);
            T3_1 = xor(T4_1, T3_1);
            T3_2 = xor(T4_2, T3_2);
            T3_3 = xor(T4_3, T3_3);
        }

        /* Accumulate non-redused result */

        T4_0 = bslli_epi128(T3_0, 8);
        T4_1 = bslli_epi128(T3_1, 8);
        T4_2 = bslli_epi128(T3_2, 8);
        T4_3 = bslli_epi128(T3_3, 8);

        T3_0 = bsrli_epi128(T3_0, 8);
        T3_1 = bsrli_epi128(T3_1, 8);
        T3_2 = bsrli_epi128(T3_2, 8);
        T3_3 = bsrli_epi128(T3_3, 8);

        T2_0 = xor(T2_0, T4_0);
        T2_1 = xor(T2_1, T4_1);
        T2_2 = xor(T2_2, T4_2);
        T2_3 = xor(T2_3, T4_3);

        T1_0 = xor(T1_0, T3_0);
        T1_1 = xor(T1_1, T3_1);
        T1_2 = xor(T1_2, T3_2);
        T1_3 = xor(T1_3, T3_3);

        /* First phase of the reduction */

        T3_0 = clmul(M512(gcm_poly2), T2_0, 0x01);
        T3_1 = clmul(M512(gcm_poly2), T2_1, 0x01);
        T3_2 = clmul(M512(gcm_poly2), T2_2, 0x01);
        T3_3 = clmul(M512(gcm_poly2), T2_3, 0x01);

        T3_0 = bslli_epi128(T3_0, 8);
        T3_1 = bslli_epi128(T3_1, 8);
        T3_2 = bslli_epi128(T3_2, 8);
        T3_3 = bslli_epi128(T3_3, 8);

        T2_0 = xor(T3_0, T2_0);
        T2_1 = xor(T3_1, T2_1);
        T2_2 = xor(T3_2, T2_2);
        T2_3 = xor(T3_3, T2_3);

        /* Second phase of the reduction */

        T3_0 = clmul(M512(gcm_poly2), T2_0, 0x00);
        T3_1 = clmul(M512(gcm_poly2), T2_1, 0x00);
        T3_2 = clmul(M512(gcm_poly2), T2_2, 0x00);
        T3_3 = clmul(M512(gcm_poly2), T2_3, 0x00);

        T3_0 = bsrli_epi128(T3_0, 4);
        T3_1 = bsrli_epi128(T3_1, 4);
        T3_2 = bsrli_epi128(T3_2, 4);
        T3_3 = bsrli_epi128(T3_3, 4);

        T4_0 = clmul(M512(gcm_poly2), T2_0, 0x10);
        T4_1 = clmul(M512(gcm_poly2), T2_1, 0x10);
        T4_2 = clmul(M512(gcm_poly2), T2_2, 0x10);
        T4_3 = clmul(M512(gcm_poly2), T2_3, 0x10);

        T4_0 = bslli_epi128(T4_0, 4);
        T4_1 = bslli_epi128(T4_1, 4);
        T4_2 = bslli_epi128(T4_2, 4);
        T4_3 = bslli_epi128(T4_3, 4);

        T4_0 = xor(T4_0, T3_0);
        T4_1 = xor(T4_1, T3_1);
        T4_2 = xor(T4_2, T3_2);
        T4_3 = xor(T4_3, T3_3);

        T4_0 = xor(T4_0, T1_0);
        T4_1 = xor(T4_1, T1_1);
        T4_2 = xor(T4_2, T1_2);
        T4_3 = xor(T4_3, T1_3);

        /* Reduction complete, store result */

        __mmask8 store_mask_0 = 0x03 * (0x1 & ((load_mask >> 0 * 4) >> 0)) | //
                                0x0C * (0x1 & ((load_mask >> 0 * 4) >> 1)) | //
                                0x30 * (0x1 & ((load_mask >> 0 * 4) >> 2)) | //
                                0xC0 * (0x1 & ((load_mask >> 0 * 4) >> 3));  //

        __mmask8 store_mask_1 = 0x03 * (0x1 & ((load_mask >> 1 * 4) >> 0)) | //
                                0x0C * (0x1 & ((load_mask >> 1 * 4) >> 1)) | //
                                0x30 * (0x1 & ((load_mask >> 1 * 4) >> 2)) | //
                                0xC0 * (0x1 & ((load_mask >> 1 * 4) >> 3));  //

        __mmask8 store_mask_2 = 0x03 * (0x1 & ((load_mask >> 2 * 4) >> 0)) | //
                                0x0C * (0x1 & ((load_mask >> 2 * 4) >> 1)) | //
                                0x30 * (0x1 & ((load_mask >> 2 * 4) >> 2)) | //
                                0xC0 * (0x1 & ((load_mask >> 2 * 4) >> 3));  //

        __mmask8 store_mask_3 = 0x03 * (0x1 & ((load_mask >> 3 * 4) >> 0)) | //
                                0x0C * (0x1 & ((load_mask >> 3 * 4) >> 1)) | //
                                0x30 * (0x1 & ((load_mask >> 3 * 4) >> 2)) | //
                                0xC0 * (0x1 & ((load_mask >> 3 * 4) >> 3));  //

        mask_storeu_epi64(ghash + 0, store_mask_0, T4_0);
        mask_storeu_epi64(ghash + 4, store_mask_1, T4_1);
        mask_storeu_epi64(ghash + 8, store_mask_2, T4_2);
        mask_storeu_epi64(ghash + 12, store_mask_3, T4_3);

        /* Update pointers and lengths */

        (*input_len) =
            mask_sub_epi32((*input_len), load_mask, (*input_len), set1_epi32(16 * stream_len));

        __mmask8 ptr_update_mask_lo = load_mask & 0xFF;
        __mmask8 ptr_update_mask_hi = (load_mask >> 8) & 0xFF;

        __m512i loc_pa_input_lo = loadu(pa_input);
        __m512i loc_pa_input_hi = loadu(pa_input + 8);

        loc_pa_input_lo = mask_add_epi64(
            loc_pa_input_lo, ptr_update_mask_lo, loc_pa_input_lo, set1_epi64(16 * stream_len));
        loc_pa_input_hi = mask_add_epi64(
            loc_pa_input_hi, ptr_update_mask_hi, loc_pa_input_hi, set1_epi64(16 * stream_len));

        storeu((void*)pa_input, loc_pa_input_lo);
        storeu((void*)(pa_input + 8), loc_pa_input_hi);

        stream_len = 0;
        load_mask  = 0;

        /* Calculate how many blocks can be processed with delayed reduction */
        for (int i = 8; i > 0; i--) {
            __mmask16 max_stream_len_mask =
                cmp_epi32_mask((*input_len), set1_epi32(16 * i), _MM_CMPINT_GE);
            __mmask16 less_16_mask = cmp_epi32_mask((*input_len), set1_epi32(16), _MM_CMPINT_LT);
            __mmask16 stream_mask  = max_stream_len_mask | less_16_mask;

            load_mask =
                load_mask * (load_mask != 0) | max_stream_len_mask * (stream_mask == 0xFFFF) *
                                                   (load_mask == 0) * (less_16_mask != 0xFFFF);
            stream_len = stream_len +
                         i * (stream_mask == 0xFFFF) * (stream_len == 0) * (less_16_mask != 0xFFFF);
        }

        load_mask &= mb_mask;
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
