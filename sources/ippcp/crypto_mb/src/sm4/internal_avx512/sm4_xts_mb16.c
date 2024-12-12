/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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

#define FIRST_TWEAKS 1
#define NEXT_TWEAKS  0

/* Generate the next 4 tweaks for a given buffer */
static void generate_next_4_tweaks(const __m512i* PREV_TWEAK,
                                   __m512i* NEXT_TWEAK,
                                   const __m512i z_shuf_mask,
                                   const __m512i z_poly,
                                   const int first_tweaks)
{
    __m512i TMP1, TMP2, TMP3, TMP4;
    const __mmask8 xor_mask = _cvtu32_mask8(0xAA);

    TMP1 = _mm512_shuffle_epi8(*PREV_TWEAK, z_shuf_mask);
    /*
     * In case of the first 4 tweaks, the shifts are variable,
     * as we are start from tweak 1 in all 128-bit lanes, to construct
     * tweaks 1, 2, 3 and 4
     */
    if (first_tweaks) {
        const __m512i z_dq3210 = _mm512_loadu_si512(xts_const_dq3210);
        const __m512i z_dq5678 = _mm512_loadu_si512(xts_const_dq5678);

        TMP2 = _mm512_sllv_epi64(*PREV_TWEAK, z_dq3210);
        TMP3 = _mm512_srlv_epi64(TMP1, z_dq5678);
        /*
     * For following tweaks, the shifts are constant,
     * as we calculate the next 4 tweaks, parting from tweaks N-4, N-3, N-2 and N,
     * to construct tweaks N, N+1, N+2, N+3
     */
    } else {
        TMP2 = _mm512_slli_epi64(*PREV_TWEAK, 4);
        TMP3 = _mm512_srli_epi64(TMP1, 4);
    }
    TMP4        = _mm512_clmulepi64_epi128(TMP3, z_poly, 0);
    TMP2        = _mm512_mask_xor_epi64(TMP2, xor_mask, TMP2, TMP3);
    *NEXT_TWEAK = _mm512_xor_epi32(TMP4, TMP2);
}

/* Prepare the last tweaks for a given buffer, if it has a partial block */
static void prepare_last_tweaks(__m512i* TWEAK,
                                __m512i* NEXT_TWEAK,
                                const int operation,
                                int num_remain_full_blocks)
{
    /*
     * For the encryption case, we need to prepare the tweak
     * for the partial block to be at the beginning of NEXT_TWEAK,
     * so depending on the number of remaining full blocks, its position
     * will vary, so the permute mask will be different. In case, there are 4 full blocks,
     * the newly generated NEXT_TWEAK will be positioned correctly.
     */
    if (operation == SM4_ENC) {
        if (num_remain_full_blocks == 1)
            *NEXT_TWEAK =
                _mm512_permutexvar_epi64(_mm512_loadu_si512(&xts_next_tweak_permq_enc[0]), *TWEAK);
        else if (num_remain_full_blocks == 2)
            *NEXT_TWEAK = _mm512_permutexvar_epi64(
                _mm512_loadu_si512(&xts_next_tweak_permq_enc[1 * 8]), *TWEAK);
        else if (num_remain_full_blocks == 3)
            *NEXT_TWEAK = _mm512_permutexvar_epi64(
                _mm512_loadu_si512(&xts_next_tweak_permq_enc[2 * 8]), *TWEAK);
        /*
     * For the decryption case, it is a bit more complicated.
     * In case of a partial block, the last two tweaks (the last tweak of the last full block)
     * and the tweak of the last block, need to be interchanged.
     * TWEAK will have the tweaks for the last FULL blocks and *NEXT_TWEAK,
     * as earlier, will have the tweak for the last partial block.
     */
    } else {
        if (num_remain_full_blocks == 1) {
            *NEXT_TWEAK =
                _mm512_permutexvar_epi64(_mm512_loadu_si512(&xts_next_tweak_permq[0]), *TWEAK);
            *TWEAK = _mm512_permutexvar_epi64(_mm512_loadu_si512(&xts_tweak_permq[0]), *TWEAK);
        } else if (num_remain_full_blocks == 2) {
            *NEXT_TWEAK =
                _mm512_permutexvar_epi64(_mm512_loadu_si512(&xts_next_tweak_permq[1 * 8]), *TWEAK);
            *TWEAK = _mm512_permutexvar_epi64(_mm512_loadu_si512(&xts_tweak_permq[1 * 8]), *TWEAK);
        } else if (num_remain_full_blocks == 3) {
            *NEXT_TWEAK =
                _mm512_permutexvar_epi64(_mm512_loadu_si512(&xts_next_tweak_permq[2 * 8]), *TWEAK);
            *TWEAK = _mm512_permutexvar_epi64(_mm512_loadu_si512(&xts_tweak_permq[2 * 8]), *TWEAK);
        } else if (num_remain_full_blocks == 4) {
            *NEXT_TWEAK = _mm512_permutex2var_epi64(
                *NEXT_TWEAK, _mm512_loadu_si512(&xts_next_tweak_permq[3 * 8]), *TWEAK);
            *TWEAK = _mm512_permutex2var_epi64(
                *TWEAK, _mm512_loadu_si512(&xts_tweak_permq[3 * 8]), *NEXT_TWEAK);
        }
    }
}

static void sm4_xts_mask_kernel_mb16(__m512i* NEXT_TWEAK,
                                     const __m512i* p_rk,
                                     __m512i loc_len32,
                                     const int8u** loc_inp,
                                     int8u** loc_out,
                                     __mmask16 mb_mask,
                                     const int operation)
{
    __m512i TMP[20];
    const __m512i z_poly               = _mm512_loadu_si512(xts_poly);
    const __m512i z_partial_block_mask = _mm512_loadu_si512(xts_partial_block_mask);
    const __m512i z_full_block_mask    = _mm512_loadu_si512(xts_full_block_mask);
    const __m512i z_shuf_mask          = _mm512_loadu_si512(xts_shuf_mask);
    /* Length in bytes of partial blocks for all buffers */
    const __m512i partial_len32 = _mm512_and_si512(loc_len32, z_partial_block_mask);
    /* Length in bytes of full blocks for all buffers */
    loc_len32 = _mm512_and_si512(loc_len32, z_full_block_mask);

    __mmask16 ge_64_mask = _mm512_mask_cmp_epi32_mask(
        mb_mask, loc_len32, _mm512_set1_epi32(4 * SM4_BLOCK_SIZE), _MM_CMPINT_NLT);
    __mmask8 ge_64_mask_0_7  = (__mmask8)ge_64_mask;
    __mmask8 ge_64_mask_8_15 = (__mmask8)_kshiftri_mask16(ge_64_mask, 8);
    /* Expand 32-bit lengths to 64-bit lengths for 16 buffers */
    const __mmask16 expand_mask = _cvtu32_mask16(0x5555);
    __m512i remain_len64_0_7    = _mm512_maskz_permutexvar_epi32(
        expand_mask, _mm512_loadu_si512(xts_dw0_7_to_qw_idx), loc_len32);
    __m512i remain_len64_8_15 = _mm512_maskz_permutexvar_epi32(
        expand_mask, _mm512_loadu_si512(xts_dw8_15_to_qw_idx), loc_len32);
    __m512i processed_len64_0_7;
    __m512i processed_len64_8_15;
    __m512i TWEAK[SM4_LINES];
    __m512i num_remain_full_blocks = _mm512_srli_epi32(loc_len32, 4);
    /* Calculate bitmask of buffers with at least one full block */
    __mmask16 tmp_mask =
        _mm512_mask_cmp_epi32_mask(mb_mask, loc_len32, _mm512_set1_epi32(0), _MM_CMPINT_NLE);

    /*
     * While there is at least one full block in any of the buffer, keep encrypting
     * (this loop only handles full blocks, but some buffers will have here
     * less than 4 full blocks)
     */
    while (tmp_mask) {
        /* Mask for data loading */
        __mmask64 stream_mask[16];
        int i;

        int* p_loc_len32              = (int*)&loc_len32;
        int* p_num_remain_full_blocks = (int*)&num_remain_full_blocks;
        int* p_partial_block          = (int*)&partial_len32;

        /* Generate tweaks for next rounds */
        for (i = 0; i < SM4_LINES; i++) {
            TWEAK[i] = NEXT_TWEAK[i];
            /*
             * If there are at least 4 more full blocks to process,
             * at least one more tweak will be needed (for more full blocks or
             * for a last partial block)
             */
            if (p_num_remain_full_blocks[i] >= 4)
                generate_next_4_tweaks(&TWEAK[i], &NEXT_TWEAK[i], z_shuf_mask, z_poly, NEXT_TWEAKS);

            /* If there is a partial block, tweaks need to be rearranged depending on cipher direction */
            if ((p_partial_block[i] > 0) & (p_num_remain_full_blocks[i] <= 4))
                prepare_last_tweaks(
                    &TWEAK[i], &NEXT_TWEAK[i], operation, p_num_remain_full_blocks[i]);
        }

        num_remain_full_blocks = _mm512_sub_epi32(num_remain_full_blocks, _mm512_set1_epi32(4));

        /*
         * XOR plaintext from each lane with the 4 tweaks and transpose to prepare for encryption.
         * Since some buffers will have less than 4 full blocks,
         * a bitmask is required to load less than 64 bytes (stream_mask)
         */
        UPDATE_STREAM_MASK_64(stream_mask[0], p_loc_len32)
        TMP[0] = _mm512_xor_si512(TWEAK[0], _mm512_maskz_loadu_epi8(stream_mask[0], loc_inp[0]));
        UPDATE_STREAM_MASK_64(stream_mask[1], p_loc_len32)
        TMP[1] = _mm512_xor_si512(TWEAK[1], _mm512_maskz_loadu_epi8(stream_mask[1], loc_inp[1]));
        UPDATE_STREAM_MASK_64(stream_mask[2], p_loc_len32)
        TMP[2] = _mm512_xor_si512(TWEAK[2], _mm512_maskz_loadu_epi8(stream_mask[2], loc_inp[2]));
        UPDATE_STREAM_MASK_64(stream_mask[3], p_loc_len32)
        TMP[3] = _mm512_xor_si512(TWEAK[3], _mm512_maskz_loadu_epi8(stream_mask[3], loc_inp[3]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));

        TRANSPOSE_INP_512(TMP[4], TMP[5], TMP[6], TMP[7], TMP[0], TMP[1], TMP[2], TMP[3]);

        UPDATE_STREAM_MASK_64(stream_mask[4], p_loc_len32)
        TMP[0] = _mm512_xor_si512(TWEAK[4], _mm512_maskz_loadu_epi8(stream_mask[4], loc_inp[4]));
        UPDATE_STREAM_MASK_64(stream_mask[5], p_loc_len32)
        TMP[1] = _mm512_xor_si512(TWEAK[5], _mm512_maskz_loadu_epi8(stream_mask[5], loc_inp[5]));
        UPDATE_STREAM_MASK_64(stream_mask[6], p_loc_len32)
        TMP[2] = _mm512_xor_si512(TWEAK[6], _mm512_maskz_loadu_epi8(stream_mask[6], loc_inp[6]));
        UPDATE_STREAM_MASK_64(stream_mask[7], p_loc_len32)
        TMP[3] = _mm512_xor_si512(TWEAK[7], _mm512_maskz_loadu_epi8(stream_mask[7], loc_inp[7]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));

        TRANSPOSE_INP_512(TMP[8], TMP[9], TMP[10], TMP[11], TMP[0], TMP[1], TMP[2], TMP[3]);

        UPDATE_STREAM_MASK_64(stream_mask[8], p_loc_len32)
        TMP[0] = _mm512_xor_si512(TWEAK[8], _mm512_maskz_loadu_epi8(stream_mask[8], loc_inp[8]));
        UPDATE_STREAM_MASK_64(stream_mask[9], p_loc_len32)
        TMP[1] = _mm512_xor_si512(TWEAK[9], _mm512_maskz_loadu_epi8(stream_mask[9], loc_inp[9]));
        UPDATE_STREAM_MASK_64(stream_mask[10], p_loc_len32)
        TMP[2] = _mm512_xor_si512(TWEAK[10], _mm512_maskz_loadu_epi8(stream_mask[10], loc_inp[10]));
        UPDATE_STREAM_MASK_64(stream_mask[11], p_loc_len32)
        TMP[3] = _mm512_xor_si512(TWEAK[11], _mm512_maskz_loadu_epi8(stream_mask[11], loc_inp[11]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));

        TRANSPOSE_INP_512(TMP[12], TMP[13], TMP[14], TMP[15], TMP[0], TMP[1], TMP[2], TMP[3]);

        UPDATE_STREAM_MASK_64(stream_mask[12], p_loc_len32)
        TMP[0] = _mm512_xor_si512(TWEAK[12], _mm512_maskz_loadu_epi8(stream_mask[12], loc_inp[12]));
        UPDATE_STREAM_MASK_64(stream_mask[13], p_loc_len32)
        TMP[1] = _mm512_xor_si512(TWEAK[13], _mm512_maskz_loadu_epi8(stream_mask[13], loc_inp[13]));
        UPDATE_STREAM_MASK_64(stream_mask[14], p_loc_len32)
        TMP[2] = _mm512_xor_si512(TWEAK[14], _mm512_maskz_loadu_epi8(stream_mask[14], loc_inp[14]));
        UPDATE_STREAM_MASK_64(stream_mask[15], p_loc_len32)
        TMP[3] = _mm512_xor_si512(TWEAK[15], _mm512_maskz_loadu_epi8(stream_mask[15], loc_inp[15]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));

        TRANSPOSE_INP_512(TMP[16], TMP[17], TMP[18], TMP[19], TMP[0], TMP[1], TMP[2], TMP[3]);

        SM4_KERNEL(TMP, p_rk, operation);
        p_rk -= operation * SM4_ROUNDS;

        /* Transpose, XOR with the tweaks again and write data out */
        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], TMP[5], TMP[6], TMP[7]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[0], stream_mask[0], _mm512_xor_si512(TMP[0], TWEAK[0]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[1], stream_mask[1], _mm512_xor_si512(TMP[1], TWEAK[1]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[2], stream_mask[2], _mm512_xor_si512(TMP[2], TWEAK[2]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[3], stream_mask[3], _mm512_xor_si512(TMP[3], TWEAK[3]));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[8], TMP[9], TMP[10], TMP[11]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[4], stream_mask[4], _mm512_xor_si512(TMP[0], TWEAK[4]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[5], stream_mask[5], _mm512_xor_si512(TMP[1], TWEAK[5]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[6], stream_mask[6], _mm512_xor_si512(TMP[2], TWEAK[6]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[7], stream_mask[7], _mm512_xor_si512(TMP[3], TWEAK[7]));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[12], TMP[13], TMP[14], TMP[15]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[8], stream_mask[8], _mm512_xor_si512(TMP[0], TWEAK[8]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[9], stream_mask[9], _mm512_xor_si512(TMP[1], TWEAK[9]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[10], stream_mask[10], _mm512_xor_si512(TMP[2], TWEAK[10]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[11], stream_mask[11], _mm512_xor_si512(TMP[3], TWEAK[11]));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[16], TMP[17], TMP[18], TMP[19]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[12], stream_mask[12], _mm512_xor_si512(TMP[0], TWEAK[12]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[13], stream_mask[13], _mm512_xor_si512(TMP[1], TWEAK[13]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[14], stream_mask[14], _mm512_xor_si512(TMP[2], TWEAK[14]));
        _mm512_mask_storeu_epi8(
            (__m512i*)loc_out[15], stream_mask[15], _mm512_xor_si512(TMP[3], TWEAK[15]));

        /* Update input/output pointers to data */
        processed_len64_0_7 = _mm512_mask_blend_epi64(
            ge_64_mask_0_7, remain_len64_0_7, _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));
        processed_len64_8_15 = _mm512_mask_blend_epi64(
            ge_64_mask_8_15, remain_len64_8_15, _mm512_set1_epi64(4 * SM4_BLOCK_SIZE));
        M512(loc_inp)     = _mm512_add_epi64(_mm512_loadu_si512(loc_inp), processed_len64_0_7);
        M512(loc_inp + 8) = _mm512_add_epi64(_mm512_loadu_si512(loc_inp + 8), processed_len64_8_15);

        M512(loc_out)     = _mm512_add_epi64(_mm512_loadu_si512(loc_out), processed_len64_0_7);
        M512(loc_out + 8) = _mm512_add_epi64(_mm512_loadu_si512(loc_out + 8), processed_len64_8_15);

        /* Update number of blocks left and processing mask */
        remain_len64_0_7  = _mm512_sub_epi64(remain_len64_0_7, processed_len64_0_7);
        remain_len64_8_15 = _mm512_sub_epi64(remain_len64_8_15, processed_len64_8_15);
        loc_len32         = _mm512_sub_epi32(loc_len32, _mm512_set1_epi32(4 * SM4_BLOCK_SIZE));
        tmp_mask =
            _mm512_mask_cmp_epi32_mask(mb_mask, loc_len32, _mm512_set1_epi32(0), _MM_CMPINT_NLE);
        ge_64_mask_0_7 = _mm512_cmp_epi64_mask(
            remain_len64_0_7, _mm512_set1_epi64(4 * SM4_BLOCK_SIZE), _MM_CMPINT_NLT);
        ge_64_mask_8_15 = _mm512_cmp_epi64_mask(
            remain_len64_8_15, _mm512_set1_epi64(4 * SM4_BLOCK_SIZE), _MM_CMPINT_NLT);
    }

    /* At this stage, all buffers have at most 15 bytes (a partial block) */

    /* Calculate bitmask of buffers with a partial block */
    tmp_mask =
        _mm512_mask_cmp_epi32_mask(mb_mask, partial_len32, _mm512_set1_epi32(0), _MM_CMPINT_NLE);

    if (tmp_mask) {
        /* Encrypt last plaintext using bytes from previous ciphertext block */
        __mmask64 stream_mask[16];
        int* p_loc_len32 = (int*)&partial_len32;
        __m128i XTMP[16];
        int i;

        for (i = 0; i < SM4_LINES; i++) {
            /* Get right tweak (position tweak in last 16 bytes of ZMM register) */
            UPDATE_STREAM_MASK_64(stream_mask[i], p_loc_len32);
            /* Read final bytes of input partial block */
            XTMP[i] = _mm_maskz_loadu_epi8((__mmask16)stream_mask[i], loc_inp[i]);
            /*
             * Read last bytes of previous output block to form 16 bytes
             * (only if there is a partial block at the end of the buffer)
             */
            if (stream_mask[i] == 0)
                continue;
            __m128i XOUT = _mm_maskz_loadu_epi8((__mmask16)~stream_mask[i], (loc_out[i] - 16));
            XTMP[i]      = _mm_or_si128(XTMP[i], XOUT);
            /* Initial XOR of new constructed input with tweak */
            XTMP[i] = _mm_xor_si128(XTMP[i], _mm512_castsi512_si128(NEXT_TWEAK[i]));
        }

        /* Encrypt final block from all lanes, compressing the 16 XMMs into 4 ZMMs */
        TRANSPOSE_16x4_I32_XMM_EPI32(&TMP[0], &TMP[1], &TMP[2], &TMP[3], XTMP);
        for (i = 0; i < SM4_ROUNDS; i += 4, p_rk += 4 * operation)
            SM4_FOUR_ROUNDS(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], p_rk, operation);

        p_rk -= operation * SM4_ROUNDS;

        /* Spread out the 4 ZMMs into 16 XMMs */
        TRANSPOSE_4x16_I32_XMM_EPI32(&TMP[0], &TMP[1], &TMP[2], &TMP[3], XTMP);
        for (i = 0; i < SM4_LINES; i++) {
            /* Skip the buffer if there is no partial block left */
            if (stream_mask[i] == 0)
                continue;
            /*
             * Final XOR of output with tweak (it will be always
             * in the beginning of NEXT_TWEAK, hence the cast)
             */
            XTMP[i] = _mm_xor_si128(XTMP[i], _mm512_castsi512_si128(NEXT_TWEAK[i]));
            /* Write first bytes of previous output block as the output of the partial block */
            __m128i XOUT = _mm_maskz_loadu_epi8((__mmask16)stream_mask[i], (loc_out[i] - 16));
            _mm_mask_storeu_epi8(loc_out[i], (__mmask16)stream_mask[i], XOUT);
            /* Write last output as the output of the previous block */
            _mm_storeu_si128((__m128i*)(loc_out[i] - 16), XTMP[i]);
        }
    }
    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8])TMP, sizeof(TMP) / sizeof(TMP[0]));
}

mbx_status16 sm4_xts_kernel_mb16(int8u* pa_out[SM4_LINES],
                                 const int8u* pa_inp[SM4_LINES],
                                 const int len[SM4_LINES],
                                 const int32u* key_sched1[SM4_ROUNDS],
                                 const int32u* key_sched2[SM4_ROUNDS],
                                 const int8u* pa_tweak[SM4_LINES],
                                 __mmask16 mb_mask,
                                 const int operation)
{
    mbx_status16 status = 0;
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];

    /* Create the local copy of the input data length in bytes and set it to zero for non-valid buffers */
    __m512i loc_len;
    loc_len = _mm512_loadu_si512(len);
    loc_len = _mm512_mask_set1_epi32(loc_len, ~mb_mask, 0);

    /* Local copies of the pointers to input and output buffers */
    _mm512_storeu_si512((void*)loc_inp, _mm512_loadu_si512(pa_inp));
    _mm512_storeu_si512((void*)(loc_inp + 8), _mm512_loadu_si512(pa_inp + 8));

    _mm512_storeu_si512(loc_out, _mm512_loadu_si512(pa_out));
    _mm512_storeu_si512(loc_out + 8, _mm512_loadu_si512(pa_out + 8));

    /* Depending on the operation(enc or dec): sign allows to go up and down on the key schedule
     * p_rk set to the beginning or to the end of the key schedule */
    const __m512i* p_rk1 = (operation == SM4_ENC) ? (const __m512i*)key_sched1
                                                  : ((const __m512i*)key_sched1 + (SM4_ROUNDS - 1));
    /* Pointer p_rk2 is set to the beginning of the key schedule,
     * as it always encrypts the tweak, regardless the direction */
    const __m512i* p_rk2 = (const __m512i*)key_sched2;

    /* TMP[] - temporary buffer for processing */
    /* TWEAK - tweak values for current blocks (4 blocks per buffer) */
    /* NEXT_TWEAK - tweak values for following blocks (4 blocks per buffer) */
    /* inital_tweak - first tweak for all buffers */
    __m512i TMP[20];
    __m512i TWEAK[SM4_LINES];
    __m512i NEXT_TWEAK[SM4_LINES];
    __m128i initial_tweak[SM4_LINES];
    int i;

    const __m512i z_poly      = _mm512_loadu_si512(xts_poly);
    const __m512i z_shuf_mask = _mm512_loadu_si512(xts_shuf_mask);

    /* Encrypt initial tweak */
    TRANSPOSE_16x4_I32_EPI32(&TMP[0], &TMP[1], &TMP[2], &TMP[3], pa_tweak, mb_mask);

    for (i = 0; i < SM4_ROUNDS; i += 4, p_rk2 += 4)
        SM4_FOUR_ROUNDS(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], p_rk2, SM4_ENC);

    p_rk2 -= SM4_ROUNDS;

    TRANSPOSE_4x16_I32_O128_EPI32(&TMP[0], &TMP[1], &TMP[2], &TMP[3], initial_tweak, mb_mask);

    /* Load TWEAK value from valid buffers and generate first 4 values */
    for (i = 0; i < SM4_LINES; i++) {
        TWEAK[i] = _mm512_broadcast_i64x2(initial_tweak[i]);
        generate_next_4_tweaks(&TWEAK[i], &NEXT_TWEAK[i], z_shuf_mask, z_poly, FIRST_TWEAKS);
    }

    /*
     * Generate the mask to process 4 full blocks from each buffer.
     * Less than 5 full blocks requires sm4_xts_mask_kernel_mb16 to handle it,
     * as it is the function that can handle partial blocks.
     */
    __mmask16 tmp_mask = _mm512_mask_cmp_epi32_mask(
        mb_mask, loc_len, _mm512_set1_epi32(5 * SM4_BLOCK_SIZE), _MM_CMPINT_NLT);

    /* Go to this loop if all 16 buffers contain at least 5 full blocks each */
    while (tmp_mask == 0xFFFF) {
        for (i = 0; i < SM4_LINES; i++) {
            TWEAK[i] = NEXT_TWEAK[i];

            /* Update tweaks for next rounds */
            generate_next_4_tweaks(&TWEAK[i], &NEXT_TWEAK[i], z_shuf_mask, z_poly, NEXT_TWEAKS);
        }

        /* XOR plaintext from each lane with the 4 tweaks and transpose to prepare for encryption */
        TMP[0] = _mm512_xor_si512(TWEAK[0], _mm512_loadu_si512(loc_inp[0]));
        TMP[1] = _mm512_xor_si512(TWEAK[1], _mm512_loadu_si512(loc_inp[1]));
        TMP[2] = _mm512_xor_si512(TWEAK[2], _mm512_loadu_si512(loc_inp[2]));
        TMP[3] = _mm512_xor_si512(TWEAK[3], _mm512_loadu_si512(loc_inp[3]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));

        TRANSPOSE_INP_512(TMP[4], TMP[5], TMP[6], TMP[7], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_xor_si512(TWEAK[4], _mm512_loadu_si512(loc_inp[4]));
        TMP[1] = _mm512_xor_si512(TWEAK[5], _mm512_loadu_si512(loc_inp[5]));
        TMP[2] = _mm512_xor_si512(TWEAK[6], _mm512_loadu_si512(loc_inp[6]));
        TMP[3] = _mm512_xor_si512(TWEAK[7], _mm512_loadu_si512(loc_inp[7]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));

        TRANSPOSE_INP_512(TMP[8], TMP[9], TMP[10], TMP[11], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_xor_si512(TWEAK[8], _mm512_loadu_si512(loc_inp[8]));
        TMP[1] = _mm512_xor_si512(TWEAK[9], _mm512_loadu_si512(loc_inp[9]));
        TMP[2] = _mm512_xor_si512(TWEAK[10], _mm512_loadu_si512(loc_inp[10]));
        TMP[3] = _mm512_xor_si512(TWEAK[11], _mm512_loadu_si512(loc_inp[11]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));

        TRANSPOSE_INP_512(TMP[12], TMP[13], TMP[14], TMP[15], TMP[0], TMP[1], TMP[2], TMP[3]);

        TMP[0] = _mm512_xor_si512(TWEAK[12], _mm512_loadu_si512(loc_inp[12]));
        TMP[1] = _mm512_xor_si512(TWEAK[13], _mm512_loadu_si512(loc_inp[13]));
        TMP[2] = _mm512_xor_si512(TWEAK[14], _mm512_loadu_si512(loc_inp[14]));
        TMP[3] = _mm512_xor_si512(TWEAK[15], _mm512_loadu_si512(loc_inp[15]));
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));

        TRANSPOSE_INP_512(TMP[16], TMP[17], TMP[18], TMP[19], TMP[0], TMP[1], TMP[2], TMP[3]);

        SM4_KERNEL(TMP, p_rk1, operation);
        p_rk1 -= operation * SM4_ROUNDS;

        /* Transpose, XOR with the tweaks again and write data out */
        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[4], TMP[5], TMP[6], TMP[7]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        _mm512_storeu_si512((__m512i*)loc_out[0], _mm512_xor_si512(TMP[0], TWEAK[0]));
        _mm512_storeu_si512((__m512i*)loc_out[1], _mm512_xor_si512(TMP[1], TWEAK[1]));
        _mm512_storeu_si512((__m512i*)loc_out[2], _mm512_xor_si512(TMP[2], TWEAK[2]));
        _mm512_storeu_si512((__m512i*)loc_out[3], _mm512_xor_si512(TMP[3], TWEAK[3]));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[8], TMP[9], TMP[10], TMP[11]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        _mm512_storeu_si512((__m512i*)loc_out[4], _mm512_xor_si512(TMP[0], TWEAK[4]));
        _mm512_storeu_si512((__m512i*)loc_out[5], _mm512_xor_si512(TMP[1], TWEAK[5]));
        _mm512_storeu_si512((__m512i*)loc_out[6], _mm512_xor_si512(TMP[2], TWEAK[6]));
        _mm512_storeu_si512((__m512i*)loc_out[7], _mm512_xor_si512(TMP[3], TWEAK[7]));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[12], TMP[13], TMP[14], TMP[15]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        _mm512_storeu_si512((__m512i*)loc_out[8], _mm512_xor_si512(TMP[0], TWEAK[8]));
        _mm512_storeu_si512((__m512i*)loc_out[9], _mm512_xor_si512(TMP[1], TWEAK[9]));
        _mm512_storeu_si512((__m512i*)loc_out[10], _mm512_xor_si512(TMP[2], TWEAK[10]));
        _mm512_storeu_si512((__m512i*)loc_out[11], _mm512_xor_si512(TMP[3], TWEAK[11]));

        TRANSPOSE_OUT_512(TMP[0], TMP[1], TMP[2], TMP[3], TMP[16], TMP[17], TMP[18], TMP[19]);
        TMP[0] = _mm512_shuffle_epi8(TMP[0], M512(swapBytes));
        TMP[1] = _mm512_shuffle_epi8(TMP[1], M512(swapBytes));
        TMP[2] = _mm512_shuffle_epi8(TMP[2], M512(swapBytes));
        TMP[3] = _mm512_shuffle_epi8(TMP[3], M512(swapBytes));
        _mm512_storeu_si512((__m512i*)loc_out[13], _mm512_xor_si512(TMP[1], TWEAK[13]));
        _mm512_storeu_si512((__m512i*)loc_out[13], _mm512_xor_si512(TMP[1], TWEAK[13]));
        _mm512_storeu_si512((__m512i*)loc_out[14], _mm512_xor_si512(TMP[2], TWEAK[14]));
        _mm512_storeu_si512((__m512i*)loc_out[15], _mm512_xor_si512(TMP[3], TWEAK[15]));

        /* Update input/output pointers to data */
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
            mb_mask, loc_len, _mm512_set1_epi32(5 * SM4_BLOCK_SIZE), _MM_CMPINT_NLT);
    }

    /* Check if we have any data left on any of the buffers */
    tmp_mask = _mm512_mask_cmp_epi32_mask(mb_mask, loc_len, _mm512_setzero_si512(), _MM_CMPINT_NLE);
    /*
     * At this point, at least one buffer has less than 5 full blocks,
     * so dealing with a partial block might be needed.
     */
    if (tmp_mask)
        sm4_xts_mask_kernel_mb16(NEXT_TWEAK, p_rk1, loc_len, loc_inp, loc_out, mb_mask, operation);

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8])TMP, sizeof(TMP) / sizeof(TMP[0]));
    zero_mb8((int64u(*)[8])TWEAK, sizeof(TWEAK) / sizeof(TWEAK[0]));

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
