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
                             __m512i* input_len,
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

    __m128i input_block_0 = _mm_maskz_loadu_epi8(
        (0xFFFF >> (16 - *((int*)input_len + (0 + 4 * 0)))) * (0x1 & load_mask_0),
        (void*)pa_input[0 + 4 * 0]);
    __m128i input_block_1 = _mm_maskz_loadu_epi8(
        (0xFFFF >> (16 - *((int*)input_len + (0 + 4 * 1)))) * (0x1 & load_mask_1),
        (void*)pa_input[0 + 4 * 1]);
    __m128i input_block_2 = _mm_maskz_loadu_epi8(
        (0xFFFF >> (16 - *((int*)input_len + (0 + 4 * 2)))) * (0x1 & load_mask_2),
        (void*)pa_input[0 + 4 * 2]);
    __m128i input_block_3 = _mm_maskz_loadu_epi8(
        (0xFFFF >> (16 - *((int*)input_len + (0 + 4 * 3)))) * (0x1 & load_mask_3),
        (void*)pa_input[0 + 4 * 3]);

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

    input_block_0 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (1 + 4 * 0)))) *
                                             (0x1 & load_mask_0),
                                         (void*)pa_input[1 + 4 * 0]);
    input_block_1 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (1 + 4 * 1)))) *
                                             (0x1 & load_mask_1),
                                         (void*)pa_input[1 + 4 * 1]);
    input_block_2 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (1 + 4 * 2)))) *
                                             (0x1 & load_mask_2),
                                         (void*)pa_input[1 + 4 * 2]);
    input_block_3 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (1 + 4 * 3)))) *
                                             (0x1 & load_mask_3),
                                         (void*)pa_input[1 + 4 * 3]);

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

    input_block_0 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (2 + 4 * 0)))) *
                                             (0x1 & load_mask_0),
                                         (void*)pa_input[2 + 4 * 0]);
    input_block_1 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (2 + 4 * 1)))) *
                                             (0x1 & load_mask_1),
                                         (void*)pa_input[2 + 4 * 1]);
    input_block_2 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (2 + 4 * 2)))) *
                                             (0x1 & load_mask_2),
                                         (void*)pa_input[2 + 4 * 2]);
    input_block_3 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (2 + 4 * 3)))) *
                                             (0x1 & load_mask_3),
                                         (void*)pa_input[2 + 4 * 3]);

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

    input_block_0 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (3 + 4 * 0)))) *
                                             (0x1 & load_mask_0),
                                         (void*)pa_input[3 + 4 * 0]);
    input_block_1 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (3 + 4 * 1)))) *
                                             (0x1 & load_mask_1),
                                         (void*)pa_input[3 + 4 * 1]);
    input_block_2 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (3 + 4 * 2)))) *
                                             (0x1 & load_mask_2),
                                         (void*)pa_input[3 + 4 * 2]);
    input_block_3 = _mm_maskz_loadu_epi8((0xFFFF >> (16 - *((int*)input_len + (3 + 4 * 3)))) *
                                             (0x1 & load_mask_3),
                                         (void*)pa_input[3 + 4 * 3]);

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
// This function updates 16 blocks of ghash by processing partial blocks ( < 128 bit blocks) of data
//
// This code is a port of GCM part of Intel(R) IPSec AES-GCM code
// Code modified to work with multi-buffer approach
*/
void sm4_gcm_update_ghash_partial_blocks_mb16(__m128i ghash[SM4_LINES],
                                              const int8u* const pa_input[SM4_LINES],
                                              __m512i* input_len,
                                              __m128i hashkey[SM4_LINES],
                                              __mmask16 mb_mask)
{
    __m512i hashkeys_4_0, hashkeys_4_1, hashkeys_4_2, hashkeys_4_3;
    __m512i* hashkeys[] = { &hashkeys_4_0, &hashkeys_4_1, &hashkeys_4_2, &hashkeys_4_3 };

    __m512i data_blocks_4_0, data_blocks_4_1, data_blocks_4_2, data_blocks_4_3;
    __m512i* data_blocks[] = {
        &data_blocks_4_0, &data_blocks_4_1, &data_blocks_4_2, &data_blocks_4_3
    };

    __mmask16 load_mask = ~cmp_epi32_mask((*input_len), setzero(), _MM_CMPINT_EQ) & mb_mask;

    if (load_mask) {

        hashkeys_4_0 = loadu(hashkey + 0);
        hashkeys_4_1 = loadu(hashkey + 4);
        hashkeys_4_2 = loadu(hashkey + 8);
        hashkeys_4_3 = loadu(hashkey + 12);

        read_first(data_blocks, pa_input, input_len, load_mask);

        data_blocks_4_0 = xor(data_blocks_4_0, loadu(ghash + 0));
        data_blocks_4_1 = xor(data_blocks_4_1, loadu(ghash + 4));
        data_blocks_4_2 = xor(data_blocks_4_2, loadu(ghash + 8));
        data_blocks_4_3 = xor(data_blocks_4_3, loadu(ghash + 12));

        sm4_gcm_ghash_mul_single_block_mb16(data_blocks, hashkeys);

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

        mask_storeu_epi64(ghash + 0, store_mask_0, data_blocks_4_0);
        mask_storeu_epi64(ghash + 4, store_mask_1, data_blocks_4_1);
        mask_storeu_epi64(ghash + 8, store_mask_2, data_blocks_4_2);
        mask_storeu_epi64(ghash + 12, store_mask_3, data_blocks_4_3);
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
