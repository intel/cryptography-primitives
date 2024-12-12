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
#include <internal/rsa/ifma_rsa_arith.h> /* for zero_mb8 */

#if (_MBX >= _MBX_K1)

/*
// These functions performs GCTR encryption/decryption
// Implementation is the same with SM4-CTR
*/

__MBX_INLINE __m128i IncBlock128(__m128i x, int32u increment)
{
    return _mm_add_epi32(x, _mm_maskz_loadu_epi32(1, &increment));
}

static void sm4_gctr_mask_kernel_mb16(__m512i* CTR,
                                      const __m512i* p_rk,
                                      __m512i loc_len,
                                      const int8u** loc_inp,
                                      int8u** loc_out,
                                      int8u* inc,
                                      __mmask16 tmp_mask,
                                      __mmask16 mb_mask)
{
    __m512i TMP[20];
    while (tmp_mask) {
        *CTR       = inc_block32(*CTR, inc);
        *(CTR + 1) = inc_block32(*(CTR + 1), inc);
        *(CTR + 2) = inc_block32(*(CTR + 2), inc);
        *(CTR + 3) = inc_block32(*(CTR + 3), inc);
        TMP[0]     = shuffle_epi8(*CTR, M512(swapWordsOrder));
        TMP[1]     = shuffle_epi8(*(CTR + 1), M512(swapWordsOrder));
        TMP[2]     = shuffle_epi8(*(CTR + 2), M512(swapWordsOrder));
        TMP[3]     = shuffle_epi8(*(CTR + 3), M512(swapWordsOrder));
        TRANSPOSE_INP_512(TMP[4], TMP[5], TMP[6], TMP[7], TMP[0], TMP[1], TMP[2], TMP[3]);

        *(CTR + 4) = inc_block32(*(CTR + 4), inc);
        *(CTR + 5) = inc_block32(*(CTR + 5), inc);
        *(CTR + 6) = inc_block32(*(CTR + 6), inc);
        *(CTR + 7) = inc_block32(*(CTR + 7), inc);
        TMP[0]     = shuffle_epi8(*(CTR + 4), M512(swapWordsOrder));
        TMP[1]     = shuffle_epi8(*(CTR + 5), M512(swapWordsOrder));
        TMP[2]     = shuffle_epi8(*(CTR + 6), M512(swapWordsOrder));
        TMP[3]     = shuffle_epi8(*(CTR + 7), M512(swapWordsOrder));
        TRANSPOSE_INP_512(TMP[8], TMP[9], TMP[10], TMP[11], TMP[0], TMP[1], TMP[2], TMP[3]);

        *(CTR + 8)  = inc_block32(*(CTR + 8), inc);
        *(CTR + 9)  = inc_block32(*(CTR + 9), inc);
        *(CTR + 10) = inc_block32(*(CTR + 10), inc);
        *(CTR + 11) = inc_block32(*(CTR + 11), inc);
        TMP[0]      = shuffle_epi8(*(CTR + 8), M512(swapWordsOrder));
        TMP[1]      = shuffle_epi8(*(CTR + 9), M512(swapWordsOrder));
        TMP[2]      = shuffle_epi8(*(CTR + 10), M512(swapWordsOrder));
        TMP[3]      = shuffle_epi8(*(CTR + 11), M512(swapWordsOrder));
        TRANSPOSE_INP_512(TMP[12], TMP[13], TMP[14], TMP[15], TMP[0], TMP[1], TMP[2], TMP[3]);

        *(CTR + 12) = inc_block32(*(CTR + 12), inc);
        *(CTR + 13) = inc_block32(*(CTR + 13), inc);
        *(CTR + 14) = inc_block32(*(CTR + 14), inc);
        *(CTR + 15) = inc_block32(*(CTR + 15), inc);
        TMP[0]      = shuffle_epi8(*(CTR + 12), M512(swapWordsOrder));
        TMP[1]      = shuffle_epi8(*(CTR + 13), M512(swapWordsOrder));
        TMP[2]      = shuffle_epi8(*(CTR + 14), M512(swapWordsOrder));
        TMP[3]      = shuffle_epi8(*(CTR + 15), M512(swapWordsOrder));
        TRANSPOSE_INP_512(TMP[16], TMP[17], TMP[18], TMP[19], TMP[0], TMP[1], TMP[2], TMP[3]);

        SM4_KERNEL(TMP, p_rk, 1);
        p_rk -= SM4_ROUNDS;

        /* Mask for data loading */
        __mmask64 stream_mask;
        int* p_loc_len = (int*)&loc_len;

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], TMP[5], TMP[6], TMP[7]);
        TMP[0] = shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = shuffle_epi8(TMP[3], M512(swapBytes));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[0],
                         stream_mask,
                         xor(TMP[0], maskz_loadu_epi8(stream_mask, loc_inp[0])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[1],
                         stream_mask,
                         xor(TMP[1], maskz_loadu_epi8(stream_mask, loc_inp[1])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[2],
                         stream_mask,
                         xor(TMP[2], maskz_loadu_epi8(stream_mask, loc_inp[2])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[3],
                         stream_mask,
                         xor(TMP[3], maskz_loadu_epi8(stream_mask, loc_inp[3])));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[8], TMP[9], TMP[10], TMP[11]);
        TMP[0] = shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = shuffle_epi8(TMP[3], M512(swapBytes));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[4],
                         stream_mask,
                         xor(TMP[0], maskz_loadu_epi8(stream_mask, loc_inp[4])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[5],
                         stream_mask,
                         xor(TMP[1], maskz_loadu_epi8(stream_mask, loc_inp[5])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[6],
                         stream_mask,
                         xor(TMP[2], maskz_loadu_epi8(stream_mask, loc_inp[6])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[7],
                         stream_mask,
                         xor(TMP[3], maskz_loadu_epi8(stream_mask, loc_inp[7])));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[12], TMP[13], TMP[14], TMP[15]);
        TMP[0] = shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = shuffle_epi8(TMP[3], M512(swapBytes));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[8],
                         stream_mask,
                         xor(TMP[0], maskz_loadu_epi8(stream_mask, loc_inp[8])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[9],
                         stream_mask,
                         xor(TMP[1], maskz_loadu_epi8(stream_mask, loc_inp[9])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[10],
                         stream_mask,
                         xor(TMP[2], maskz_loadu_epi8(stream_mask, loc_inp[10])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[11],
                         stream_mask,
                         xor(TMP[3], maskz_loadu_epi8(stream_mask, loc_inp[11])));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[16], TMP[17], TMP[18], TMP[19]);
        TMP[0] = shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = shuffle_epi8(TMP[3], M512(swapBytes));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[12],
                         stream_mask,
                         xor(TMP[0], maskz_loadu_epi8(stream_mask, loc_inp[12])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[13],
                         stream_mask,
                         xor(TMP[1], maskz_loadu_epi8(stream_mask, loc_inp[13])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[14],
                         stream_mask,
                         xor(TMP[2], maskz_loadu_epi8(stream_mask, loc_inp[14])));
        UPDATE_STREAM_MASK_64(stream_mask, p_loc_len)
        mask_storeu_epi8((__m512i*)loc_out[15],
                         stream_mask,
                         xor(TMP[3], maskz_loadu_epi8(stream_mask, loc_inp[15])));

        /* Update pointers to data */
        M512(loc_inp)     = add_epi64(loadu(loc_inp), set1_epi64(4 * SM4_BLOCK_SIZE));
        M512(loc_inp + 8) = add_epi64(loadu(loc_inp + 8), set1_epi64(4 * SM4_BLOCK_SIZE));

        M512(loc_out)     = add_epi64(loadu(loc_out), set1_epi64(4 * SM4_BLOCK_SIZE));
        M512(loc_out + 8) = add_epi64(loadu(loc_out + 8), set1_epi64(4 * SM4_BLOCK_SIZE));

        /* Update number of blocks left and processing mask */
        loc_len  = sub_epi32(loc_len, set1_epi32(4 * SM4_BLOCK_SIZE));
        tmp_mask = mask_cmp_epi32_mask(mb_mask, loc_len, set1_epi32(0), _MM_CMPINT_NLE);
        inc      = (int8u*)nextInc;
    }

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8])TMP, sizeof(TMP) / sizeof(TMP[0]));
}

void sm4_gctr_kernel_mb16(int8u* pa_out[SM4_LINES],
                          const int8u* const pa_inp[SM4_LINES],
                          const int len[SM4_LINES],
                          const int32u* key_sched[SM4_ROUNDS],
                          __mmask16 mb_mask,
                          SM4_GCM_CTX_mb16* p_context)
{
    __mmask16 loc_mb_mask = 0;

    for (int i = 0; i < SM4_LINES; i++) {
        __mmask16 tmp = mb_mask & (0x1 << rearrangeOrder[i]);
        tmp           = tmp >> rearrangeOrder[i];
        loc_mb_mask   = loc_mb_mask | tmp << i;
    }

    mb_mask = loc_mb_mask;

    const int8u* loc_inp[SM4_LINES];
    int8u* loc_out[SM4_LINES];

    /* Create the local copy of the input data length in bytes and set it to zero for non-valid buffers */
    __m512i loc_len;
    loc_len = loadu(len);
    loc_len = mask_set1_epi32(loc_len, ~mb_mask, 0);

    /* input blocks loc_blks[] = ceil(loc_len[]/SM4_BLOCK_SIZE) */
    int32u loc_blks[SM4_LINES];
    storeu(loc_blks, srli_epi32(add_epi32(loc_len, set1_epi32(SM4_BLOCK_SIZE - 1)), 4));

    /* Local copies of the pointers to input and output buffers */
    storeu((void*)loc_inp, loadu(pa_inp));
    storeu((void*)(loc_inp + 8), loadu(pa_inp + 8));

    storeu(loc_out, loadu(pa_out));
    storeu(loc_out + 8, loadu(pa_out + 8));

    /* Pointer p_rk is set to the beginning of the key schedule */
    const __m512i* p_rk = (const __m512i*)key_sched;

    /* TMP[] - temporary buffer for processing */
    /* CTR - store CTR values                  */
    __m512i TMP[20];
    __m512i CTR[SM4_LINES];
    __m128i loc_ctr[SM4_LINES];

    /* Load CTR value from valid buffers and rearrange it */
    mb_mask            = mask_cmp_epi32_mask(mb_mask, loc_len, setzero(), _MM_CMPINT_NLE);
    int ctrRearrange[] = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
    for (int i = 0; i < SM4_LINES; i++) {
        if (0x1 & (mb_mask >> i)) {
            loc_ctr[i] = _mm_loadu_si128(SM4_GCM_CONTEXT_CTR(p_context) + ctrRearrange[i]);
        } else {
            loc_ctr[i] = _mm_setzero_si128();
        }

        CTR[i] = broadcast_i64x2(loc_ctr[i]);
    }

    /* Generate the mask to process 4 blocks from each buffer */
    __mmask16 tmp_mask =
        mask_cmp_epi32_mask(mb_mask, loc_len, set1_epi32(4 * SM4_BLOCK_SIZE), _MM_CMPINT_NLT);

    int8u* inc = (int8u*)firstInc;

    /* Go to this loop if all 16 buffers contain at least 4 blocks each */
    while (tmp_mask == 0xFFFF) {
        CTR[0] = inc_block32(CTR[0], inc);
        CTR[1] = inc_block32(CTR[1], inc);
        CTR[2] = inc_block32(CTR[2], inc);
        CTR[3] = inc_block32(CTR[3], inc);
        TMP[0] = shuffle_epi8(CTR[0], M512(swapWordsOrder));
        TMP[1] = shuffle_epi8(CTR[1], M512(swapWordsOrder));
        TMP[2] = shuffle_epi8(CTR[2], M512(swapWordsOrder));
        TMP[3] = shuffle_epi8(CTR[3], M512(swapWordsOrder));
        TRANSPOSE_INP_512(TMP[4], TMP[5], TMP[6], TMP[7], TMP[0], TMP[1], TMP[2], TMP[3]);

        CTR[4] = inc_block32(CTR[4], inc);
        CTR[5] = inc_block32(CTR[5], inc);
        CTR[6] = inc_block32(CTR[6], inc);
        CTR[7] = inc_block32(CTR[7], inc);
        TMP[0] = shuffle_epi8(CTR[4], M512(swapWordsOrder));
        TMP[1] = shuffle_epi8(CTR[5], M512(swapWordsOrder));
        TMP[2] = shuffle_epi8(CTR[6], M512(swapWordsOrder));
        TMP[3] = shuffle_epi8(CTR[7], M512(swapWordsOrder));
        TRANSPOSE_INP_512(TMP[8], TMP[9], TMP[10], TMP[11], TMP[0], TMP[1], TMP[2], TMP[3]);

        CTR[8]  = inc_block32(CTR[8], inc);
        CTR[9]  = inc_block32(CTR[9], inc);
        CTR[10] = inc_block32(CTR[10], inc);
        CTR[11] = inc_block32(CTR[11], inc);
        TMP[0]  = shuffle_epi8(CTR[8], M512(swapWordsOrder));
        TMP[1]  = shuffle_epi8(CTR[9], M512(swapWordsOrder));
        TMP[2]  = shuffle_epi8(CTR[10], M512(swapWordsOrder));
        TMP[3]  = shuffle_epi8(CTR[11], M512(swapWordsOrder));
        TRANSPOSE_INP_512(TMP[12], TMP[13], TMP[14], TMP[15], TMP[0], TMP[1], TMP[2], TMP[3]);

        CTR[12] = inc_block32(CTR[12], inc);
        CTR[13] = inc_block32(CTR[13], inc);
        CTR[14] = inc_block32(CTR[14], inc);
        CTR[15] = inc_block32(CTR[15], inc);
        TMP[0]  = shuffle_epi8(CTR[12], M512(swapWordsOrder));
        TMP[1]  = shuffle_epi8(CTR[13], M512(swapWordsOrder));
        TMP[2]  = shuffle_epi8(CTR[14], M512(swapWordsOrder));
        TMP[3]  = shuffle_epi8(CTR[15], M512(swapWordsOrder));
        TRANSPOSE_INP_512(TMP[16], TMP[17], TMP[18], TMP[19], TMP[0], TMP[1], TMP[2], TMP[3]);

        SM4_KERNEL(TMP, p_rk, 1);
        p_rk -= SM4_ROUNDS;

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], TMP[5], TMP[6], TMP[7]);
        TMP[0] = shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = shuffle_epi8(TMP[3], M512(swapBytes));
        storeu((__m512i*)loc_out[0], xor(TMP[0], loadu(loc_inp[0])));
        storeu((__m512i*)loc_out[1], xor(TMP[1], loadu(loc_inp[1])));
        storeu((__m512i*)loc_out[2], xor(TMP[2], loadu(loc_inp[2])));
        storeu((__m512i*)loc_out[3], xor(TMP[3], loadu(loc_inp[3])));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[8], TMP[9], TMP[10], TMP[11]);
        TMP[0] = shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = shuffle_epi8(TMP[3], M512(swapBytes));
        storeu((__m512i*)loc_out[4], xor(TMP[0], loadu(loc_inp[4])));
        storeu((__m512i*)loc_out[5], xor(TMP[1], loadu(loc_inp[5])));
        storeu((__m512i*)loc_out[6], xor(TMP[2], loadu(loc_inp[6])));
        storeu((__m512i*)loc_out[7], xor(TMP[3], loadu(loc_inp[7])));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[12], TMP[13], TMP[14], TMP[15]);
        TMP[0] = shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = shuffle_epi8(TMP[3], M512(swapBytes));
        storeu((__m512i*)loc_out[8], xor(TMP[0], loadu(loc_inp[8])));
        storeu((__m512i*)loc_out[9], xor(TMP[1], loadu(loc_inp[9])));
        storeu((__m512i*)loc_out[10], xor(TMP[2], loadu(loc_inp[10])));
        storeu((__m512i*)loc_out[11], xor(TMP[3], loadu(loc_inp[11])));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[16], TMP[17], TMP[18], TMP[19]);
        TMP[0] = shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = shuffle_epi8(TMP[3], M512(swapBytes));
        storeu((__m512i*)loc_out[12], xor(TMP[0], loadu(loc_inp[12])));
        storeu((__m512i*)loc_out[13], xor(TMP[1], loadu(loc_inp[13])));
        storeu((__m512i*)loc_out[14], xor(TMP[2], loadu(loc_inp[14])));
        storeu((__m512i*)loc_out[15], xor(TMP[3], loadu(loc_inp[15])));

        /* Update pointers to data */
        M512(loc_inp)     = add_epi64(loadu(loc_inp), set1_epi64(4 * SM4_BLOCK_SIZE));
        M512(loc_inp + 8) = add_epi64(loadu(loc_inp + 8), set1_epi64(4 * SM4_BLOCK_SIZE));

        M512(loc_out)     = add_epi64(loadu(loc_out), set1_epi64(4 * SM4_BLOCK_SIZE));
        M512(loc_out + 8) = add_epi64(loadu(loc_out + 8), set1_epi64(4 * SM4_BLOCK_SIZE));

        /* Update number of blocks left and processing mask */
        loc_len = sub_epi32(loc_len, set1_epi32(4 * SM4_BLOCK_SIZE));
        tmp_mask =
            mask_cmp_epi32_mask(mb_mask, loc_len, set1_epi32(4 * SM4_BLOCK_SIZE), _MM_CMPINT_NLT);
        inc = (int8u*)nextInc;
    }

    /* Check if we have any data */
    tmp_mask = mask_cmp_epi32_mask(mb_mask, loc_len, setzero(), _MM_CMPINT_NLE);
    if (tmp_mask) {
        sm4_gctr_mask_kernel_mb16(CTR, p_rk, loc_len, loc_inp, loc_out, inc, tmp_mask, mb_mask);
    }

    /* update and store counters */
    for (int i = 0; i < SM4_LINES; i++) {
        if (0x1 & (mb_mask >> i)) {
            loc_ctr[i] = IncBlock128(loc_ctr[i], loc_blks[i]);
            _mm_storeu_si128(SM4_GCM_CONTEXT_CTR(p_context) + ctrRearrange[i], loc_ctr[i]);
            loc_ctr[i] = _mm_setzero_si128();
        }
    }

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8])TMP, sizeof(TMP) / sizeof(TMP[0]));
    zero_mb8((int64u(*)[8])CTR, sizeof(CTR) / sizeof(CTR[0]));
}

#endif /* #if (_MBX>=_MBX_K1) */
