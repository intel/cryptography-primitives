/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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

#include <internal/sm4/sm4_mb.h>
#include <internal/rsa/ifma_rsa_arith.h>
#include <internal/common/ifma_defs.h>

#if (_MBX >= _MBX_K1)

mbx_status16 sm4_cbc_enc_kernel_mb16(int8u* pa_out[SM4_LINES],
                                     const int8u* pa_inp[SM4_LINES],
                                     const int len[SM4_LINES],
                                     const int32u* key_sched[SM4_ROUNDS],
                                     __mmask16 mb_mask,
                                     const int8u* pa_iv[SM4_LINES])
{
    mbx_status16 status = 0;
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];

    /* Length of the input data in 128-bit chunks - number of SM4 blocks */
    __m512i num_blocks;
    GET_NUM_BLOCKS(num_blocks, len, SM4_BLOCK_SIZE);

    /* Local copies of the pointers to input and output buffers */
    _mm512_storeu_si512((void*)loc_inp, _mm512_loadu_si512(pa_inp));
    _mm512_storeu_si512((void*)(loc_inp + 8), _mm512_loadu_si512(pa_inp + 8));

    _mm512_storeu_si512(loc_out, _mm512_loadu_si512(pa_out));
    _mm512_storeu_si512(loc_out + 8, _mm512_loadu_si512(pa_out + 8));

    /* Set p_rk pointer to the beginning of the key schedule */
    const __m512i* p_rk = (const __m512i*)key_sched;

    /* Check if we have any data */
    __mmask16 tmp_mask =
        _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_setzero_si512(), _MM_CMPINT_NLE);

    __m512i iv0, iv1, iv2, iv3;
    __m512i z0, z1, z2, z3, xi;

    /* Load and transpose iv */
    TRANSPOSE_16x4_I32_EPI32(&iv0, &iv1, &iv2, &iv3, pa_iv, tmp_mask);

    while (tmp_mask) {
        /* Transpose input data */
        TRANSPOSE_16x4_I32_EPI32(&z0, &z1, &z2, &z3, loc_inp, tmp_mask);

        z0 = _mm512_xor_epi32(z0, iv0);
        z1 = _mm512_xor_epi32(z1, iv1);
        z2 = _mm512_xor_epi32(z2, iv2);
        z3 = _mm512_xor_epi32(z3, iv3);

        for (int itr = 0; itr < SM4_ROUNDS; itr += 4, p_rk += 4)
            SM4_FOUR_ROUNDS(z0, z1, z2, z3, xi, p_rk, 1);

        p_rk -= SM4_ROUNDS;

        iv0 = z3;
        iv1 = z2;
        iv2 = z1;
        iv3 = z0;

        /* Transpose and store encrypted blocks */
        TRANSPOSE_4x16_I32_EPI32(&z0, &z1, &z2, &z3, loc_out, tmp_mask);

        /* Update pointers to data */
        _mm512_storeu_si512(
            (void*)loc_inp,
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(SM4_BLOCK_SIZE)));
        _mm512_storeu_si512(
            (void*)(loc_inp + 8),
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE)));

        _mm512_storeu_si512(
            loc_out,
            _mm512_add_epi64(_mm512_loadu_si512(loc_out), _mm512_set1_epi64(SM4_BLOCK_SIZE)));
        _mm512_storeu_si512(
            (loc_out + 8),
            _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE)));

        /* Update number of blocks left and processing mask */
        num_blocks = _mm512_sub_epi32(num_blocks, _mm512_set1_epi32(1));
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_setzero_si512(), _MM_CMPINT_NLE);
    }

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8]) & z0, 1);
    zero_mb8((int64u(*)[8]) & z1, 1);
    zero_mb8((int64u(*)[8]) & z2, 1);
    zero_mb8((int64u(*)[8]) & z3, 1);
    zero_mb8((int64u(*)[8]) & xi, 1);
    return status;
}

/*
 * Perform SM4-CBC-MAC on 16 buffers and generate their authentication tag.
 *
 * @param[out] pa_out   Array of pointers to authentication tag
 * @param[in] pa_in     Array of pointers to input buffers
 * @param[in] len       Array of buffer lengths
 * @param[in] key_sched Array of SM4 scheduled keys
 * @param[in] mb_mask   Bitmask selecting which lines to generate tag
 * @param[in] pa_iv     Array of IV pointers
 */
void sm4_cbc_mac_kernel_mb16(__m128i pa_out[SM4_LINES],
                             const int8u* const pa_inp[SM4_LINES],
                             const int len[SM4_LINES],
                             const int32u* key_sched[SM4_ROUNDS],
                             __mmask16 mb_mask,
                             const int8u* pa_iv[SM4_LINES])
{
    __ALIGN64 const int8u* loc_inp[SM4_LINES];

    /* Length of the input data in 128-bit chunks - number of SM4 blocks */
    __m512i num_blocks;
    GET_NUM_BLOCKS(num_blocks, len, SM4_BLOCK_SIZE);

    /* Local copies of the pointers to input buffers */
    _mm512_storeu_si512((void*)loc_inp, _mm512_loadu_si512(pa_inp));
    _mm512_storeu_si512((void*)(loc_inp + 8), _mm512_loadu_si512(pa_inp + 8));

    /* Set p_rk pointer to the beginning of the key schedule */
    const __m512i* p_rk = (const __m512i*)key_sched;

    /* Check if we have any data */
    __mmask16 tmp_mask =
        _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_setzero_si512(), _MM_CMPINT_NLE);
    __m512i iv0, iv1, iv2, iv3;
    __m512i z0, z1, z2, z3, xi;
    __m512i in0, in1, in2, in3;

    mb_mask = tmp_mask;

    z0 = _mm512_setzero_si512();
    z1 = _mm512_setzero_si512();
    z2 = _mm512_setzero_si512();
    z3 = _mm512_setzero_si512();

    /* Load and transpose iv */
    TRANSPOSE_16x4_I32_EPI32(&iv0, &iv1, &iv2, &iv3, pa_iv, tmp_mask);

    while (tmp_mask) {
        /* Transpose input data */
        TRANSPOSE_16x4_I32_EPI32(&in0, &in1, &in2, &in3, loc_inp, tmp_mask);

        z0 = _mm512_mask_xor_epi32(z0, tmp_mask, in0, iv0);
        z1 = _mm512_mask_xor_epi32(z1, tmp_mask, in1, iv1);
        z2 = _mm512_mask_xor_epi32(z2, tmp_mask, in2, iv2);
        z3 = _mm512_mask_xor_epi32(z3, tmp_mask, in3, iv3);

        for (int itr = 0; itr < SM4_ROUNDS; itr += 4, p_rk += 4)
            SM4_FOUR_ROUNDS_MASKED(z0, z1, z2, z3, xi, tmp_mask, p_rk, 1);

        p_rk -= SM4_ROUNDS;

        iv0 = z3;
        iv1 = z2;
        iv2 = z1;
        iv3 = z0;

        /* Update pointers to data */
        _mm512_storeu_si512(
            (void*)loc_inp,
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(SM4_BLOCK_SIZE)));
        _mm512_storeu_si512(
            (void*)(loc_inp + 8),
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE)));

        /* Update number of blocks left and processing mask */
        num_blocks = _mm512_sub_epi32(num_blocks, _mm512_set1_epi32(1));
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_setzero_si512(), _MM_CMPINT_NLE);
    }

    /* Transpose and store result MAC */
    TRANSPOSE_4x16_I32_O128_EPI32(&z0, &z1, &z2, &z3, pa_out, mb_mask);

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8]) & z0, 1);
    zero_mb8((int64u(*)[8]) & z1, 1);
    zero_mb8((int64u(*)[8]) & z2, 1);
    zero_mb8((int64u(*)[8]) & z3, 1);
    zero_mb8((int64u(*)[8]) & xi, 1);
}

static void sm4_cbc_dec_incomplete_buff_mb16(const int8u* loc_inp[SM4_LINES],
                                             int8u* loc_out[SM4_LINES],
                                             __m512i num_blocks,
                                             const __m512i* p_rk,
                                             __mmask16 mb_mask,
                                             __m512i TMP[20],
                                             __m512i STORED_CT[16]);

mbx_status16 sm4_cbc_dec_kernel_mb16(int8u* pa_out[SM4_LINES],
                                     const int8u* pa_inp[SM4_LINES],
                                     const int len[SM4_LINES],
                                     const int32u* key_sched[SM4_ROUNDS],
                                     __mmask16 mb_mask,
                                     const int8u* pa_iv[SM4_LINES])
{
    mbx_status16 status = 0;
    const int8u* loc_inp[SM4_LINES];
    int8u* loc_out[SM4_LINES];

    /* Load the constant value */
    const __m512i swap_m512i = _mm512_loadu_si512(swapBytes);

    /* Registers to store ciphertext blocks to be XOR'ed with output of SM4 cipher stage */
    __m512i STORED_CT[16];

    /* Length of the input data in 128-bit chunks - number of SM4 blocks */
    __m512i num_blocks;
    GET_NUM_BLOCKS(num_blocks, len, SM4_BLOCK_SIZE);

    /* Don't process empty buffers */
    mb_mask =
        _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_setzero_si512(), _MM_CMPINT_NE);

    /* Local copies of the pointers to input and output buffers */
    _mm512_storeu_si512((void*)loc_inp, _mm512_loadu_si512(pa_inp));
    _mm512_storeu_si512((void*)(loc_inp + 8), _mm512_loadu_si512(pa_inp + 8));

    _mm512_storeu_si512(loc_out, _mm512_loadu_si512(pa_out));
    _mm512_storeu_si512(loc_out + 8, _mm512_loadu_si512(pa_out + 8));

    /* Set p_rk pointer to the end of the key schedule */
    const __m512i* p_rk = (const __m512i*)key_sched + (SM4_ROUNDS - 1);

    __ALIGN64 __m512i TMP[20];
    __mmask16 loc_mb_mask = mb_mask;

    /* Store first ciphertext block for next round */
    for (int i = 0; i < SM4_LINES; i++) {
        STORED_CT[i]       = _mm512_setzero_epi32();
        __m128i data_block = _mm_maskz_loadu_epi32(0x000F * (0x1 & loc_mb_mask), loc_inp[i]);
        STORED_CT[i]       = _mm512_inserti64x2(STORED_CT[i], data_block, 3);
        loc_mb_mask >>= 1;
    }

    /* Process the first block from each buffer, because it contains IV specific */
    /* Load and transpose input data */
    TRANSPOSE_16x4_I32_EPI32(&TMP[0], &TMP[1], &TMP[2], &TMP[3], loc_inp, mb_mask);

    for (int itr = 0; itr < SM4_ROUNDS; itr += 4, p_rk -= 4)
        SM4_FOUR_ROUNDS(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], p_rk, -1);
    p_rk += SM4_ROUNDS;

    /* Transpose and store first encrypted block for each buffer */
    TRANSPOSE_AND_XOR_4x16_I32_EPI32(&TMP[0], &TMP[1], &TMP[2], &TMP[3], loc_out, pa_iv, mb_mask);

    /* Update pointers to data */
    _mm512_storeu_si512(
        (void*)loc_inp,
        _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(SM4_BLOCK_SIZE)));
    _mm512_storeu_si512(
        (void*)(loc_inp + 8),
        _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE)));

    _mm512_storeu_si512(
        loc_out, _mm512_add_epi64(_mm512_loadu_si512(loc_out), _mm512_set1_epi64(SM4_BLOCK_SIZE)));
    _mm512_storeu_si512(
        (loc_out + 8),
        _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE)));

    num_blocks = _mm512_sub_epi32(num_blocks, _mm512_set1_epi32(1));

    /* Generate the mask to process 4 blocks from each buffer */
    __mmask16 tmp_mask =
        _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_set1_epi32(4), _MM_CMPINT_NLT);

    /* Go to this loop if all 16 buffers contain at least 4 blocks each */
    while (tmp_mask == 0xFFFF) {
        TMP[0] = _mm512_loadu_si512(loc_inp[0]);
        TMP[1] = _mm512_loadu_si512((__m512i*)(loc_inp[1]));
        TMP[2] = _mm512_loadu_si512((__m512i*)(loc_inp[2]));
        TMP[3] = _mm512_loadu_si512((__m512i*)(loc_inp[3]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        TRANSPOSE_INP_512(TMP[4], TMP[5], TMP[6], TMP[7], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_loadu_si512((__m512i*)(loc_inp[4]));
        TMP[1] = _mm512_loadu_si512((__m512i*)(loc_inp[5]));
        TMP[2] = _mm512_loadu_si512((__m512i*)(loc_inp[6]));
        TMP[3] = _mm512_loadu_si512((__m512i*)(loc_inp[7]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        TRANSPOSE_INP_512(TMP[8], TMP[9], TMP[10], TMP[11], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_loadu_si512((__m512i*)(loc_inp[8]));
        TMP[1] = _mm512_loadu_si512((__m512i*)(loc_inp[9]));
        TMP[2] = _mm512_loadu_si512((__m512i*)(loc_inp[10]));
        TMP[3] = _mm512_loadu_si512((__m512i*)(loc_inp[11]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        TRANSPOSE_INP_512(TMP[12], TMP[13], TMP[14], TMP[15], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_loadu_si512((__m512i*)(loc_inp[12]));
        TMP[1] = _mm512_loadu_si512((__m512i*)(loc_inp[13]));
        TMP[2] = _mm512_loadu_si512((__m512i*)(loc_inp[14]));
        TMP[3] = _mm512_loadu_si512((__m512i*)(loc_inp[15]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        TRANSPOSE_INP_512(TMP[16], TMP[17], TMP[18], TMP[19], TMP[0], TMP[1], TMP[2], TMP[3]);

        SM4_KERNEL(TMP, p_rk, -1);

        p_rk += SM4_ROUNDS;

        for (int i = 0; i < SM4_LINES; i++)
            STORED_CT[i] = _mm512_alignr_epi64(_mm512_loadu_si512(loc_inp[i]), STORED_CT[i], 6);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], TMP[5], TMP[6], TMP[7]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        /* xor with IVs */
        TMP[4] = _mm512_xor_si512(TMP[0], STORED_CT[0]);
        TMP[5] = _mm512_xor_si512(TMP[1], STORED_CT[1]);
        TMP[6] = _mm512_xor_si512(TMP[2], STORED_CT[2]);
        TMP[7] = _mm512_xor_si512(TMP[3], STORED_CT[3]);
        /* Store last block of ciphertext for next iteration */
        for (int i = 0; i < 4; i++)
            STORED_CT[i] = _mm512_inserti64x2(
                STORED_CT[i], _mm_loadu_si128((__m128i const*)loc_inp[i] + 3), 3);
        _mm512_storeu_si512((__m512i*)(loc_out[0]), TMP[4]);
        _mm512_storeu_si512((__m512i*)(loc_out[1]), TMP[5]);
        _mm512_storeu_si512((__m512i*)(loc_out[2]), TMP[6]);
        _mm512_storeu_si512((__m512i*)(loc_out[3]), TMP[7]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[8], TMP[9], TMP[10], TMP[11]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        /* xor with IVs */
        TMP[8]  = _mm512_xor_si512(TMP[0], STORED_CT[4]);
        TMP[9]  = _mm512_xor_si512(TMP[1], STORED_CT[5]);
        TMP[10] = _mm512_xor_si512(TMP[2], STORED_CT[6]);
        TMP[11] = _mm512_xor_si512(TMP[3], STORED_CT[7]);
        /* Store last block of ciphertext for next iteration */
        for (int i = 4; i < 8; i++)
            STORED_CT[i] = _mm512_inserti64x2(
                STORED_CT[i], _mm_loadu_si128((__m128i const*)loc_inp[i] + 3), 3);
        _mm512_storeu_si512((__m512i*)(loc_out[4]), TMP[8]);
        _mm512_storeu_si512((__m512i*)(loc_out[5]), TMP[9]);
        _mm512_storeu_si512((__m512i*)(loc_out[6]), TMP[10]);
        _mm512_storeu_si512((__m512i*)(loc_out[7]), TMP[11]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[12], TMP[13], TMP[14], TMP[15]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        /* xor with IVs */
        TMP[12] = _mm512_xor_si512(TMP[0], STORED_CT[8]);
        TMP[13] = _mm512_xor_si512(TMP[1], STORED_CT[9]);
        TMP[14] = _mm512_xor_si512(TMP[2], STORED_CT[10]);
        TMP[15] = _mm512_xor_si512(TMP[3], STORED_CT[11]);
        /* Store last block of ciphertext for next iteration */
        for (int i = 8; i < 12; i++)
            STORED_CT[i] = _mm512_inserti64x2(
                STORED_CT[i], _mm_loadu_si128((__m128i const*)loc_inp[i] + 3), 3);
        _mm512_storeu_si512((__m512i*)(loc_out[8]), TMP[12]);
        _mm512_storeu_si512((__m512i*)(loc_out[9]), TMP[13]);
        _mm512_storeu_si512((__m512i*)(loc_out[10]), TMP[14]);
        _mm512_storeu_si512((__m512i*)(loc_out[11]), TMP[15]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[16], TMP[17], TMP[18], TMP[19]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        /* xor with IVs */
        TMP[16] = _mm512_xor_si512(TMP[0], STORED_CT[12]);
        TMP[17] = _mm512_xor_si512(TMP[1], STORED_CT[13]);
        TMP[18] = _mm512_xor_si512(TMP[2], STORED_CT[14]);
        TMP[19] = _mm512_xor_si512(TMP[3], STORED_CT[15]);
        for (int i = 12; i < SM4_LINES; i++)
            STORED_CT[i] = _mm512_inserti64x2(
                STORED_CT[i], _mm_loadu_si128((__m128i const*)loc_inp[i] + 3), 3);
        _mm512_storeu_si512((__m512i*)(loc_out[12]), TMP[16]);
        _mm512_storeu_si512((__m512i*)(loc_out[13]), TMP[17]);
        _mm512_storeu_si512((__m512i*)(loc_out[14]), TMP[18]);
        _mm512_storeu_si512((__m512i*)(loc_out[15]), TMP[19]);

        /* Update pointers to data */
        _mm512_storeu_si512(
            (void*)loc_inp,
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(4 * SM4_BLOCK_SIZE)));
        _mm512_storeu_si512((void*)(loc_inp + 8),
                            _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8),
                                             _mm512_set1_epi64(4 * SM4_BLOCK_SIZE)));

        _mm512_storeu_si512(
            loc_out,
            _mm512_add_epi64(_mm512_loadu_si512(loc_out), _mm512_set1_epi64(4 * SM4_BLOCK_SIZE)));
        _mm512_storeu_si512((loc_out + 8),
                            _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8),
                                             _mm512_set1_epi64(4 * SM4_BLOCK_SIZE)));

        /* Update number of blocks left and processing mask */
        num_blocks = _mm512_sub_epi32(num_blocks, _mm512_set1_epi32(4));
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_set1_epi32(4), _MM_CMPINT_NLT);
    }

    /* compute incomplete buffer loading */
    sm4_cbc_dec_incomplete_buff_mb16(loc_inp, loc_out, num_blocks, p_rk, mb_mask, TMP, STORED_CT);
    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8])TMP, sizeof(TMP) / sizeof(TMP[0]));

    return status;
}

// Disable optimization for VS19 (>= 19.27)
OPTIMIZE_OFF_VS19

static void sm4_cbc_dec_incomplete_buff_mb16(const int8u* loc_inp[SM4_LINES],
                                             int8u* loc_out[SM4_LINES],
                                             __m512i num_blocks,
                                             const __m512i* p_rk,
                                             __mmask16 mb_mask,
                                             __m512i TMP[20],
                                             __m512i STORED_CT[16])
{
    /* Load the constant value */
    const __m512i swap_m512i = _mm512_loadu_si512(swapBytes);
    /* Check if we have any data */
    __mmask16 tmp_mask =
        _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_setzero_si512(), _MM_CMPINT_NLE);

    while (tmp_mask) {
        /* Generate the array of masks for data loading. 0 - 4 blocks will be can load from each buffer - depend on the amount of remaining data */
        __ALIGN64 __mmask8 block_mask[16];

        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_set1_epi32(4), _MM_CMPINT_NLT);
        /* Will be loaded 4 blocks of data */
        M128(block_mask) = _mm_maskz_set1_epi8(tmp_mask, 0xFF);
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_set1_epi32(3), _MM_CMPINT_EQ);
        /* Will be loaded 3 blocks of data */
        M128(block_mask) = _mm_mask_set1_epi8(M128(block_mask), tmp_mask, 0x3F);
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_set1_epi32(2), _MM_CMPINT_EQ);
        /* Will be loaded 2 blocks of data */
        M128(block_mask) = _mm_mask_set1_epi8(M128(block_mask), tmp_mask, 0xF);
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_set1_epi32(1), _MM_CMPINT_EQ);
        /* Will be loaded 1 block of data */
        M128(block_mask) = _mm_mask_set1_epi8(M128(block_mask), tmp_mask, 0x3);

        TMP[0] = _mm512_maskz_loadu_epi64(block_mask[0], loc_inp[0]);
        TMP[1] = _mm512_maskz_loadu_epi64(block_mask[1], loc_inp[1]);
        TMP[2] = _mm512_maskz_loadu_epi64(block_mask[2], loc_inp[2]);
        TMP[3] = _mm512_maskz_loadu_epi64(block_mask[3], loc_inp[3]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        TRANSPOSE_INP_512(TMP[4], TMP[5], TMP[6], TMP[7], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_maskz_loadu_epi64(block_mask[4], loc_inp[4]);
        TMP[1] = _mm512_maskz_loadu_epi64(block_mask[5], loc_inp[5]);
        TMP[2] = _mm512_maskz_loadu_epi64(block_mask[6], loc_inp[6]);
        TMP[3] = _mm512_maskz_loadu_epi64(block_mask[7], loc_inp[7]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        TRANSPOSE_INP_512(TMP[8], TMP[9], TMP[10], TMP[11], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_maskz_loadu_epi64(block_mask[8], loc_inp[8]);
        TMP[1] = _mm512_maskz_loadu_epi64(block_mask[9], loc_inp[9]);
        TMP[2] = _mm512_maskz_loadu_epi64(block_mask[10], loc_inp[10]);
        TMP[3] = _mm512_maskz_loadu_epi64(block_mask[11], loc_inp[11]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        TRANSPOSE_INP_512(TMP[12], TMP[13], TMP[14], TMP[15], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_maskz_loadu_epi64(block_mask[12], loc_inp[12]);
        TMP[1] = _mm512_maskz_loadu_epi64(block_mask[13], loc_inp[13]);
        TMP[2] = _mm512_maskz_loadu_epi64(block_mask[14], loc_inp[14]);
        TMP[3] = _mm512_maskz_loadu_epi64(block_mask[15], loc_inp[15]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        TRANSPOSE_INP_512(TMP[16], TMP[17], TMP[18], TMP[19], TMP[0], TMP[1], TMP[2], TMP[3]);

        SM4_KERNEL(TMP, p_rk, -1);
        p_rk += SM4_ROUNDS;

        for (int i = 0; i < SM4_LINES; i++)
            STORED_CT[i] = _mm512_alignr_epi64(
                _mm512_maskz_loadu_epi64(block_mask[i], (__m128i* const)loc_inp[i]),
                STORED_CT[i],
                6);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], TMP[5], TMP[6], TMP[7]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        /* xor with IVs */
        TMP[4] = _mm512_xor_si512(TMP[0], STORED_CT[0]);
        TMP[5] = _mm512_xor_si512(TMP[1], STORED_CT[1]);
        TMP[6] = _mm512_xor_si512(TMP[2], STORED_CT[2]);
        TMP[7] = _mm512_xor_si512(TMP[3], STORED_CT[3]);
        /* Store last block of ciphertext for next iteration */
        for (int i = 0; i < 4; i++) {
            __mmask8 write_block_mask = _kshiftri_mask8(block_mask[i], 6);
            __m128i data_block =
                _mm_maskz_loadu_epi64(write_block_mask, (__m128i const*)loc_inp[i] + 3);
            STORED_CT[i] =
                _mm512_mask_inserti64x2(STORED_CT[i], block_mask[i], STORED_CT[i], data_block, 3);
        }
        _mm512_mask_storeu_epi64(loc_out[0], block_mask[0], TMP[4]);
        _mm512_mask_storeu_epi64(loc_out[1], block_mask[1], TMP[5]);
        _mm512_mask_storeu_epi64(loc_out[2], block_mask[2], TMP[6]);
        _mm512_mask_storeu_epi64(loc_out[3], block_mask[3], TMP[7]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[8], TMP[9], TMP[10], TMP[11]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        /* xor with IVs */
        TMP[8]  = _mm512_xor_si512(TMP[0], STORED_CT[4]);
        TMP[9]  = _mm512_xor_si512(TMP[1], STORED_CT[5]);
        TMP[10] = _mm512_xor_si512(TMP[2], STORED_CT[6]);
        TMP[11] = _mm512_xor_si512(TMP[3], STORED_CT[7]);
        /* Store last block of ciphertext for next iteration */
        for (int i = 4; i < 8; i++) {
            __mmask8 write_block_mask = _kshiftri_mask8(block_mask[i], 6);
            __m128i data_block =
                _mm_maskz_loadu_epi64(write_block_mask, (__m128i const*)loc_inp[i] + 3);
            STORED_CT[i] =
                _mm512_mask_inserti64x2(STORED_CT[i], block_mask[i], STORED_CT[i], data_block, 3);
        }
        _mm512_mask_storeu_epi64(loc_out[4], block_mask[4], TMP[8]);
        _mm512_mask_storeu_epi64(loc_out[5], block_mask[5], TMP[9]);
        _mm512_mask_storeu_epi64(loc_out[6], block_mask[6], TMP[10]);
        _mm512_mask_storeu_epi64(loc_out[7], block_mask[7], TMP[11]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[12], TMP[13], TMP[14], TMP[15]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        /* xor with IVs */
        TMP[12] = _mm512_xor_si512(TMP[0], STORED_CT[8]);
        TMP[13] = _mm512_xor_si512(TMP[1], STORED_CT[9]);
        TMP[14] = _mm512_xor_si512(TMP[2], STORED_CT[10]);
        TMP[15] = _mm512_xor_si512(TMP[3], STORED_CT[11]);
        /* Store last block of ciphertext for next iteration */
        for (int i = 8; i < 12; i++) {
            __mmask8 write_block_mask = _kshiftri_mask8(block_mask[i], 6);
            __m128i data_block =
                _mm_maskz_loadu_epi64(write_block_mask, (__m128i const*)loc_inp[i] + 3);
            STORED_CT[i] =
                _mm512_mask_inserti64x2(STORED_CT[i], block_mask[i], STORED_CT[i], data_block, 3);
        }
        _mm512_mask_storeu_epi64(loc_out[8], block_mask[8], TMP[12]);
        _mm512_mask_storeu_epi64(loc_out[9], block_mask[9], TMP[13]);
        _mm512_mask_storeu_epi64(loc_out[10], block_mask[10], TMP[14]);
        _mm512_mask_storeu_epi64(loc_out[11], block_mask[11], TMP[15]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[16], TMP[17], TMP[18], TMP[19]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], swap_m512i);
        TMP[1] = _mm512_shuffle_epi8(TMP[1], swap_m512i);
        TMP[2] = _mm512_shuffle_epi8(TMP[2], swap_m512i);
        TMP[3] = _mm512_shuffle_epi8(TMP[3], swap_m512i);
        /* xor with IVs */
        TMP[16] = _mm512_xor_si512(TMP[0], STORED_CT[12]);
        TMP[17] = _mm512_xor_si512(TMP[1], STORED_CT[13]);
        TMP[18] = _mm512_xor_si512(TMP[2], STORED_CT[14]);
        TMP[19] = _mm512_xor_si512(TMP[3], STORED_CT[15]);
        /* Store last block of ciphertext for next iteration */
        for (int i = 12; i < SM4_LINES; i++) {
            __mmask8 write_block_mask = _kshiftri_mask8(block_mask[i], 6);
            __m128i data_block =
                _mm_maskz_loadu_epi64(write_block_mask, (__m128i const*)loc_inp[i] + 3);
            STORED_CT[i] =
                _mm512_mask_inserti64x2(STORED_CT[i], block_mask[i], STORED_CT[i], data_block, 3);
        }
        _mm512_mask_storeu_epi64(loc_out[12], block_mask[12], TMP[16]);
        _mm512_mask_storeu_epi64(loc_out[13], block_mask[13], TMP[17]);
        _mm512_mask_storeu_epi64(loc_out[14], block_mask[14], TMP[18]);
        _mm512_mask_storeu_epi64(loc_out[15], block_mask[15], TMP[19]);

        /* Update pointers to data */
        _mm512_storeu_si512(
            (void*)loc_inp,
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(4 * SM4_BLOCK_SIZE)));
        _mm512_storeu_si512((void*)(loc_inp + 8),
                            _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8),
                                             _mm512_set1_epi64(4 * SM4_BLOCK_SIZE)));

        _mm512_storeu_si512(
            loc_out,
            _mm512_add_epi64(_mm512_loadu_si512(loc_out), _mm512_set1_epi64(4 * SM4_BLOCK_SIZE)));
        _mm512_storeu_si512((loc_out + 8),
                            _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8),
                                             _mm512_set1_epi64(4 * SM4_BLOCK_SIZE)));

        /* Update the number of blocks. For some buffers, the value can become zero or a negative number - these buffers will not be processed  */
        num_blocks = _mm512_sub_epi32(num_blocks, _mm512_set1_epi32(4));

        /* Check if we have any data */
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, num_blocks, _mm512_setzero_si512(), _MM_CMPINT_NLE);
    }
    return;
}

// Enable optimization for VS19 (>= 19.27)
OPTIMIZE_ON_VS19

#endif /* #if (_MBX>=_MBX_K1) */
