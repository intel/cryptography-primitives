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

#if (_MBX >= _MBX_K1)

mbx_status16 sm4_cfb128_enc_kernel_mb16(int8u* pa_out[SM4_LINES],
                                        const int8u* pa_inp[SM4_LINES],
                                        const int len[SM4_LINES],
                                        const int32u* key_sched[SM4_ROUNDS],
                                        const int8u* pa_iv[SM4_LINES],
                                        __mmask16 mb_mask)
{
    mbx_status16 status = 0;
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];

    /* Get the copy of input data lengths in bytes */
    __m512i loc_len = _mm512_loadu_si512(len);
    int* p_loc_len  = (int*)&loc_len;

    /* Local copies of the pointers to input and output buffers */
    _mm512_storeu_si512((void*)loc_inp, _mm512_loadu_si512(pa_inp));
    _mm512_storeu_si512((void*)(loc_inp + 8), _mm512_loadu_si512(pa_inp + 8));

    _mm512_storeu_si512(loc_out, _mm512_loadu_si512(pa_out));
    _mm512_storeu_si512(loc_out + 8, _mm512_loadu_si512(pa_out + 8));

    /* Set p_rk pointer to the beginning of the key schedule */
    const __m512i* p_rk = (const __m512i*)key_sched;

    /* Check if we have any data */
    __mmask16 tmp_mask =
        _mm512_mask_cmp_epi32_mask(mb_mask, loc_len, _mm512_setzero_si512(), _MM_CMPINT_NLE);

    /* Load and transpose iv */
    __m512i iv0, iv1, iv2, iv3;
    TRANSPOSE_16x4_I32_EPI32(&iv0, &iv1, &iv2, &iv3, (const int8u**)pa_iv, tmp_mask);

    /* Main loop */
    __m512i z0, z1, z2, z3, tmp;
    while (tmp_mask) {
        for (int itr = 0; itr < SM4_ROUNDS; itr += 4, p_rk += 4)
            SM4_FOUR_ROUNDS(iv0, iv1, iv2, iv3, tmp, p_rk, 1);

        p_rk -= SM4_ROUNDS;

        /* Load and transpose plaintext */
        TRANSPOSE_16x4_I32_EPI32(&z0, &z1, &z2, &z3, (const int8u**)loc_inp, tmp_mask);

        /* Change the order of blocks (Y0, Y1, Y2, Y3) = R(X32, X33, X34, X35) = (X35, X34, X33, X32) and xor with plain text */
        tmp = iv0;
        iv0 = _mm512_xor_epi32(iv3, z0);
        iv3 = _mm512_xor_epi32(tmp, z3);
        tmp = iv1;
        iv1 = _mm512_xor_epi32(iv2, z1);
        iv2 = _mm512_xor_epi32(tmp, z2);

        /* Transpose and store encrypted blocks by bytes */
        TRANSPOSE_4x16_I32_EPI8(iv0, iv1, iv2, iv3, loc_out, p_loc_len, tmp_mask);

        /* Update pointers to data */
        M512(loc_inp) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(SM4_BLOCK_SIZE));
        M512(loc_inp + 8) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE));

        M512(loc_out) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_out), _mm512_set1_epi64(SM4_BLOCK_SIZE));
        M512(loc_out + 8) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE));

        /* Update number of blocks left and processing mask */
        loc_len = _mm512_sub_epi32(loc_len, _mm512_set1_epi32(SM4_BLOCK_SIZE));
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, loc_len, _mm512_setzero_si512(), _MM_CMPINT_NLE);
    }

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8]) & iv0, 1);
    zero_mb8((int64u(*)[8]) & iv1, 1);
    zero_mb8((int64u(*)[8]) & iv2, 1);
    zero_mb8((int64u(*)[8]) & iv3, 1);

    zero_mb8((int64u(*)[8]) & z0, 1);
    zero_mb8((int64u(*)[8]) & z1, 1);
    zero_mb8((int64u(*)[8]) & z2, 1);
    zero_mb8((int64u(*)[8]) & z3, 1);
    zero_mb8((int64u(*)[8]) & tmp, 1);

    return status;
}

static void sm4_cfb128_mask_dec_kernel_mb16(const int8u** loc_inp,
                                            int8u** loc_out,
                                            __m512i loc_len,
                                            const __m512i* p_rk,
                                            __mmask16 tmp_mask,
                                            __m512i STORED_CT[16])
{
    __m512i TMP[20];
    while (tmp_mask) {
        /* Generate the array of masks for data loading */
        __mmask64 stream_mask[16];
        int* p_loc_len = (int*)&loc_len;
        for (int i = 0; i < SM4_LINES; i++) {
            UPDATE_STREAM_MASK_64(stream_mask[i], p_loc_len);
        }

        for (int i = 0; i < SM4_LINES; i++)
            STORED_CT[i] = _mm512_alignr_epi64(
                _mm512_maskz_loadu_epi8(stream_mask[i], (__m128i* const)loc_inp[i]),
                STORED_CT[i],
                6);

        TMP[0] = _mm512_shuffle_epi8(STORED_CT[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(STORED_CT[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(STORED_CT[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(STORED_CT[3], M512(swapBytes));
        TRANSPOSE_INP_512(TMP[4], TMP[5], TMP[6], TMP[7], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_shuffle_epi8(STORED_CT[4], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(STORED_CT[5], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(STORED_CT[6], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(STORED_CT[7], M512(swapBytes));
        TRANSPOSE_INP_512(TMP[8], TMP[9], TMP[10], TMP[11], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_shuffle_epi8(STORED_CT[8], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(STORED_CT[9], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(STORED_CT[10], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(STORED_CT[11], M512(swapBytes));
        TRANSPOSE_INP_512(TMP[12], TMP[13], TMP[14], TMP[15], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_shuffle_epi8(STORED_CT[12], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(STORED_CT[13], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(STORED_CT[14], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(STORED_CT[15], M512(swapBytes));
        TRANSPOSE_INP_512(TMP[16], TMP[17], TMP[18], TMP[19], TMP[0], TMP[1], TMP[2], TMP[3]);

        SM4_KERNEL(TMP, p_rk, 1);
        p_rk -= SM4_ROUNDS;

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], TMP[5], TMP[6], TMP[7]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        /* xor with ciphertext */
        TMP[4] = _mm512_xor_si512(TMP[0], _mm512_maskz_loadu_epi8(stream_mask[0], loc_inp[0]));
        TMP[5] = _mm512_xor_si512(TMP[1], _mm512_maskz_loadu_epi8(stream_mask[1], loc_inp[1]));
        TMP[6] = _mm512_xor_si512(TMP[2], _mm512_maskz_loadu_epi8(stream_mask[2], loc_inp[2]));
        TMP[7] = _mm512_xor_si512(TMP[3], _mm512_maskz_loadu_epi8(stream_mask[3], loc_inp[3]));
        /* Store last block of ciphertext for next iteration */
        for (int i = 0; i < 4; i++) {
            __mmask64 write_stream_mask = _kshiftri_mask64(stream_mask[i], 8 * 6);
            __m128i data_block =
                _mm_maskz_loadu_epi8((__mmask16)write_stream_mask, (__m128i const*)loc_inp[i] + 3);
            STORED_CT[i] = _mm512_inserti64x2(STORED_CT[i], data_block, 3);
        }
        _mm512_mask_storeu_epi8(loc_out[0], stream_mask[0], TMP[4]);
        _mm512_mask_storeu_epi8(loc_out[1], stream_mask[1], TMP[5]);
        _mm512_mask_storeu_epi8(loc_out[2], stream_mask[2], TMP[6]);
        _mm512_mask_storeu_epi8(loc_out[3], stream_mask[3], TMP[7]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[8], TMP[9], TMP[10], TMP[11]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        /* xor with ciphertext */
        TMP[8]  = _mm512_xor_si512(TMP[0], _mm512_maskz_loadu_epi8(stream_mask[4], loc_inp[4]));
        TMP[9]  = _mm512_xor_si512(TMP[1], _mm512_maskz_loadu_epi8(stream_mask[5], loc_inp[5]));
        TMP[10] = _mm512_xor_si512(TMP[2], _mm512_maskz_loadu_epi8(stream_mask[6], loc_inp[6]));
        TMP[11] = _mm512_xor_si512(TMP[3], _mm512_maskz_loadu_epi8(stream_mask[7], loc_inp[7]));
        /* Store last block of ciphertext for next iteration */
        for (int i = 4; i < 8; i++) {
            __mmask64 write_stream_mask = _kshiftri_mask64(stream_mask[i], 8 * 6);
            __m128i data_block =
                _mm_maskz_loadu_epi8((__mmask16)write_stream_mask, (__m128i const*)loc_inp[i] + 3);
            STORED_CT[i] = _mm512_inserti64x2(STORED_CT[i], data_block, 3);
        }
        _mm512_mask_storeu_epi8(loc_out[4], stream_mask[4], TMP[8]);
        _mm512_mask_storeu_epi8(loc_out[5], stream_mask[5], TMP[9]);
        _mm512_mask_storeu_epi8(loc_out[6], stream_mask[6], TMP[10]);
        _mm512_mask_storeu_epi8(loc_out[7], stream_mask[7], TMP[11]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[12], TMP[13], TMP[14], TMP[15]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        /* xor with ciphertext */
        TMP[12] = _mm512_xor_si512(TMP[0], _mm512_maskz_loadu_epi8(stream_mask[8], loc_inp[8]));
        TMP[13] = _mm512_xor_si512(TMP[1], _mm512_maskz_loadu_epi8(stream_mask[9], loc_inp[9]));
        TMP[14] = _mm512_xor_si512(TMP[2], _mm512_maskz_loadu_epi8(stream_mask[10], loc_inp[10]));
        TMP[15] = _mm512_xor_si512(TMP[3], _mm512_maskz_loadu_epi8(stream_mask[11], loc_inp[11]));
        /* Store last block of ciphertext for next iteration */
        for (int i = 8; i < 12; i++) {
            __mmask64 write_stream_mask = _kshiftri_mask64(stream_mask[i], 8 * 6);
            __m128i data_block =
                _mm_maskz_loadu_epi8((__mmask16)write_stream_mask, (__m128i const*)loc_inp[i] + 3);
            STORED_CT[i] = _mm512_inserti64x2(STORED_CT[i], data_block, 3);
        }
        _mm512_mask_storeu_epi8(loc_out[8], stream_mask[8], TMP[12]);
        _mm512_mask_storeu_epi8(loc_out[9], stream_mask[9], TMP[13]);
        _mm512_mask_storeu_epi8(loc_out[10], stream_mask[10], TMP[14]);
        _mm512_mask_storeu_epi8(loc_out[11], stream_mask[11], TMP[15]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[16], TMP[17], TMP[18], TMP[19]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        /* xor with ciphertext */
        TMP[16] = _mm512_xor_si512(TMP[0], _mm512_maskz_loadu_epi8(stream_mask[12], loc_inp[12]));
        TMP[17] = _mm512_xor_si512(TMP[1], _mm512_maskz_loadu_epi8(stream_mask[13], loc_inp[13]));
        TMP[18] = _mm512_xor_si512(TMP[2], _mm512_maskz_loadu_epi8(stream_mask[14], loc_inp[14]));
        TMP[19] = _mm512_xor_si512(TMP[3], _mm512_maskz_loadu_epi8(stream_mask[15], loc_inp[15]));
        /* Store last block of ciphertext for next iteration */
        for (int i = 12; i < SM4_LINES; i++) {
            __mmask64 write_stream_mask = _kshiftri_mask64(stream_mask[i], 8 * 6);
            __m128i data_block =
                _mm_maskz_loadu_epi8((__mmask16)write_stream_mask, (__m128i const*)loc_inp[i] + 3);
            STORED_CT[i] = _mm512_inserti64x2(STORED_CT[i], data_block, 3);
        }
        _mm512_mask_storeu_epi8(loc_out[12], stream_mask[12], TMP[16]);
        _mm512_mask_storeu_epi8(loc_out[13], stream_mask[13], TMP[17]);
        _mm512_mask_storeu_epi8(loc_out[14], stream_mask[14], TMP[18]);
        _mm512_mask_storeu_epi8(loc_out[15], stream_mask[15], TMP[19]);

        /* Update pointers to data */
        M512(loc_inp) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));
        M512(loc_inp + 8) = _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8),
                                             _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));

        M512(loc_out) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_out), _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));
        M512(loc_out + 8) = _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8),
                                             _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));

        /* Update the number of blocks. For some buffers, the value can become zero or a negative number - these buffers will not be processed  */
        loc_len = _mm512_sub_epi32(loc_len, _mm512_set1_epi32(4 * SM4_BLOCK_SIZE));

        /* Check if we have any data */
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(tmp_mask, loc_len, _mm512_setzero_si512(), _MM_CMPINT_NLE);
    }

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8])TMP, sizeof(TMP) / sizeof(TMP[0]));
}

mbx_status16 sm4_cfb128_dec_kernel_mb16(int8u* pa_out[SM4_LINES],
                                        const int8u* pa_inp[SM4_LINES],
                                        const int len[SM4_LINES],
                                        const int32u* key_sched[SM4_ROUNDS],
                                        const int8u* pa_iv[SM4_LINES],
                                        __mmask16 mb_mask)
{
    mbx_status16 status = 0;
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];
    /* Registers to store ciphertext blocks to be XOR'ed with output of SM4 cipher stage */
    __m512i STORED_CT[16];

    /* Get the copy of input data lengths in bytes */
    __m512i loc_len = _mm512_loadu_si512(len);

    /* Don't process empty buffers */
    mb_mask = _mm512_mask_cmp_epi32_mask(mb_mask, loc_len, _mm512_setzero_si512(), _MM_CMPINT_NLE);

    /* Local copies of the pointers to input and output buffers */
    _mm512_storeu_si512((void*)loc_inp, _mm512_loadu_si512(pa_inp));
    _mm512_storeu_si512((void*)(loc_inp + 8), _mm512_loadu_si512(pa_inp + 8));

    _mm512_storeu_si512(loc_out, _mm512_loadu_si512(pa_out));
    _mm512_storeu_si512(loc_out + 8, _mm512_loadu_si512(pa_out + 8));

    /* Set p_rk pointer to the beginning of the key schedule */
    const __m512i* p_rk = (const __m512i*)key_sched;

    __m512i TMP[20];
    __mmask16 loc_mb_mask = mb_mask;

    /* Store first ciphertext block for next round */
    for (int i = 0; i < SM4_LINES; i++) {
        STORED_CT[i]       = _mm512_setzero_epi32();
        __m128i data_block = _mm_maskz_loadu_epi32(0x000F * (0x1 & loc_mb_mask), loc_inp[i]);
        STORED_CT[i]       = _mm512_inserti64x2(STORED_CT[i], data_block, 3);
        loc_mb_mask >>= 1;
    }

    /* Process the first block from each buffer, because it contains IV specific */
    /* Load and transpose iv */
    TRANSPOSE_16x4_I32_EPI32(&TMP[4], &TMP[5], &TMP[6], &TMP[7], (const int8u**)pa_iv, mb_mask);

    for (int itr = 0; itr < SM4_ROUNDS; itr += 4, p_rk += 4)
        SM4_FOUR_ROUNDS(TMP[4], TMP[5], TMP[6], TMP[7], TMP[8], p_rk, 1);
    p_rk = (const __m512i*)key_sched;
    /* Load and transpose ciphertext */
    TRANSPOSE_16x4_I32_EPI32(
        &TMP[9], &TMP[10], &TMP[11], &TMP[12], (const int8u**)loc_inp, mb_mask);

    /* Change the order of blocks (Y0, Y1, Y2, Y3) = R(X32, X33, X34, X35) = (X35, X34, X33, X32) and xor with plain text */
    TMP[8] = TMP[4];
    TMP[4] = _mm512_xor_epi32(TMP[7], TMP[9]);
    TMP[7] = _mm512_xor_epi32(TMP[8], TMP[12]);
    TMP[8] = TMP[5];
    TMP[5] = _mm512_xor_epi32(TMP[6], TMP[10]);
    TMP[6] = _mm512_xor_epi32(TMP[8], TMP[11]);

    /* Transpose and store encrypted blocks by bytes */
    int* p_loc_len = (int*)&loc_len;
    TRANSPOSE_4x16_I32_EPI8(TMP[4], TMP[5], TMP[6], TMP[7], loc_out, p_loc_len, mb_mask);

    /* Update pointers to data */
    M512(loc_inp) =
        _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(SM4_BLOCK_SIZE));
    M512(loc_inp + 8) =
        _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE));

    M512(loc_out) =
        _mm512_add_epi64(_mm512_loadu_si512(loc_out), _mm512_set1_epi64(SM4_BLOCK_SIZE));
    M512(loc_out + 8) =
        _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8), _mm512_set1_epi64(SM4_BLOCK_SIZE));

    loc_len = _mm512_sub_epi32(loc_len, _mm512_set1_epi32(SM4_BLOCK_SIZE));

    /* Generate the mask to process 4 blocks from each buffer */
    __mmask16 tmp_mask = _mm512_mask_cmp_epi32_mask(
        mb_mask, loc_len, _mm512_set1_epi32(4 * SM4_BLOCK_SIZE), _MM_CMPINT_NLT);

    /* Go to this loop if all 16 buffers contain at least 4 blocks each */
    while (tmp_mask == 0xFFFF) {
        for (int i = 0; i < SM4_LINES; i++)
            STORED_CT[i] = _mm512_alignr_epi64(_mm512_loadu_si512(loc_inp[i]), STORED_CT[i], 6);

        TMP[0] = _mm512_shuffle_epi8(STORED_CT[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(STORED_CT[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(STORED_CT[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(STORED_CT[3], M512(swapBytes));
        TRANSPOSE_INP_512(TMP[4], TMP[5], TMP[6], TMP[7], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_shuffle_epi8(STORED_CT[4], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(STORED_CT[5], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(STORED_CT[6], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(STORED_CT[7], M512(swapBytes));
        TRANSPOSE_INP_512(TMP[8], TMP[9], TMP[10], TMP[11], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_shuffle_epi8(STORED_CT[8], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(STORED_CT[9], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(STORED_CT[10], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(STORED_CT[11], M512(swapBytes));
        TRANSPOSE_INP_512(TMP[12], TMP[13], TMP[14], TMP[15], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_shuffle_epi8(STORED_CT[12], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(STORED_CT[13], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(STORED_CT[14], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(STORED_CT[15], M512(swapBytes));
        TRANSPOSE_INP_512(TMP[16], TMP[17], TMP[18], TMP[19], TMP[0], TMP[1], TMP[2], TMP[3]);

        SM4_KERNEL(TMP, p_rk, 1);
        p_rk -= SM4_ROUNDS;

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], TMP[5], TMP[6], TMP[7]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        /* xor with ciphertext */
        TMP[4] = _mm512_xor_si512(TMP[0], _mm512_loadu_si512(loc_inp[0]));
        TMP[5] = _mm512_xor_si512(TMP[1], _mm512_loadu_si512(loc_inp[1]));
        TMP[6] = _mm512_xor_si512(TMP[2], _mm512_loadu_si512(loc_inp[2]));
        TMP[7] = _mm512_xor_si512(TMP[3], _mm512_loadu_si512(loc_inp[3]));
        /* Store last block of ciphertext for next iteration */
        for (int i = 0; i < 4; i++)
            STORED_CT[i] = _mm512_inserti64x2(
                STORED_CT[i], _mm_loadu_si128((__m128i const*)loc_inp[i] + 3), 3);
        _mm512_storeu_si512((__m512i*)(loc_out[0]), TMP[4]);
        _mm512_storeu_si512((__m512i*)(loc_out[1]), TMP[5]);
        _mm512_storeu_si512((__m512i*)(loc_out[2]), TMP[6]);
        _mm512_storeu_si512((__m512i*)(loc_out[3]), TMP[7]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[8], TMP[9], TMP[10], TMP[11]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        /* xor with ciphertext */
        TMP[8]  = _mm512_xor_si512(TMP[0], _mm512_loadu_si512(loc_inp[4]));
        TMP[9]  = _mm512_xor_si512(TMP[1], _mm512_loadu_si512(loc_inp[5]));
        TMP[10] = _mm512_xor_si512(TMP[2], _mm512_loadu_si512(loc_inp[6]));
        TMP[11] = _mm512_xor_si512(TMP[3], _mm512_loadu_si512(loc_inp[7]));
        /* Store last block of ciphertext for next iteration */
        for (int i = 4; i < 8; i++)
            STORED_CT[i] = _mm512_inserti64x2(
                STORED_CT[i], _mm_loadu_si128((__m128i const*)loc_inp[i] + 3), 3);
        _mm512_storeu_si512((__m512i*)(loc_out[4]), TMP[8]);
        _mm512_storeu_si512((__m512i*)(loc_out[5]), TMP[9]);
        _mm512_storeu_si512((__m512i*)(loc_out[6]), TMP[10]);
        _mm512_storeu_si512((__m512i*)(loc_out[7]), TMP[11]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[12], TMP[13], TMP[14], TMP[15]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        /* xor with ciphertext */
        TMP[12] = _mm512_xor_si512(TMP[0], _mm512_loadu_si512(loc_inp[8]));
        TMP[13] = _mm512_xor_si512(TMP[1], _mm512_loadu_si512(loc_inp[9]));
        TMP[14] = _mm512_xor_si512(TMP[2], _mm512_loadu_si512(loc_inp[10]));
        TMP[15] = _mm512_xor_si512(TMP[3], _mm512_loadu_si512(loc_inp[11]));
        /* Store last block of ciphertext for next iteration */
        for (int i = 8; i < 12; i++)
            STORED_CT[i] = _mm512_inserti64x2(
                STORED_CT[i], _mm_loadu_si128((__m128i const*)loc_inp[i] + 3), 3);
        _mm512_storeu_si512((__m512i*)(loc_out[8]), TMP[12]);
        _mm512_storeu_si512((__m512i*)(loc_out[9]), TMP[13]);
        _mm512_storeu_si512((__m512i*)(loc_out[10]), TMP[14]);
        _mm512_storeu_si512((__m512i*)(loc_out[11]), TMP[15]);

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[16], TMP[17], TMP[18], TMP[19]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        /* xor with ciphertext */
        TMP[16] = _mm512_xor_si512(TMP[0], _mm512_loadu_si512(loc_inp[12]));
        TMP[17] = _mm512_xor_si512(TMP[1], _mm512_loadu_si512(loc_inp[13]));
        TMP[18] = _mm512_xor_si512(TMP[2], _mm512_loadu_si512(loc_inp[14]));
        TMP[19] = _mm512_xor_si512(TMP[3], _mm512_loadu_si512(loc_inp[15]));
        for (int i = 12; i < SM4_LINES; i++)
            STORED_CT[i] = _mm512_inserti64x2(
                STORED_CT[i], _mm_loadu_si128((__m128i const*)loc_inp[i] + 3), 3);
        _mm512_storeu_si512((__m512i*)(loc_out[12]), TMP[16]);
        _mm512_storeu_si512((__m512i*)(loc_out[13]), TMP[17]);
        _mm512_storeu_si512((__m512i*)(loc_out[14]), TMP[18]);
        _mm512_storeu_si512((__m512i*)(loc_out[15]), TMP[19]);

        /* Update pointers to data */
        M512(loc_inp) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_inp), _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));
        M512(loc_inp + 8) = _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8),
                                             _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));

        M512(loc_out) =
            _mm512_add_epi64(_mm512_loadu_si512(loc_out), _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));
        M512(loc_out + 8) = _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8),
                                             _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));

        /* Update number of blocks left and processing mask */
        loc_len  = _mm512_sub_epi32(loc_len, _mm512_set1_epi32(4 * SM4_BLOCK_SIZE));
        tmp_mask = _mm512_mask_cmp_epi32_mask(
            mb_mask, loc_len, _mm512_set1_epi32(4 * SM4_BLOCK_SIZE), _MM_CMPINT_NLT);
    }

    /* Check if we have any data */
    tmp_mask = _mm512_mask_cmp_epi32_mask(mb_mask, loc_len, _mm512_setzero_si512(), _MM_CMPINT_NLE);
    if (tmp_mask)
        sm4_cfb128_mask_dec_kernel_mb16(loc_inp, loc_out, loc_len, p_rk, tmp_mask, STORED_CT);

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8])TMP, sizeof(TMP) / sizeof(TMP[0]));
    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
