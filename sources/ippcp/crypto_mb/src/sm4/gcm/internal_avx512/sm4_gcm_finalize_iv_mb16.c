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

/*
// This function performs IV finalization (computes J0) in the follow way:
// If bitlen(IV) == 96, then let J0 = IV || 0^31 ||1.
// If bitlen(IV) != 96, then let s = 128 * [bitlen(IV) / 128] - bitlen(IV), and let J0 = GHASH(IV || 0^(s+64) || bitlen(IV)).
//
// 0^s means the bit string that consists of s '0' bits here
// [x] means the least integer that is not less than the real number x here
//
// This function also encrypts J0 by calling sm4_encrypt_j0_mb16(), to use it later for tag computation
*/

void sm4_gcm_finalize_iv_mb16(const int8u* const pa_iv[SM4_LINES],
                              __mmask16 mb_mask,
                              SM4_GCM_CTX_mb16* p_context)
{
    __m128i* ctr     = SM4_GCM_CONTEXT_CTR(p_context);
    __m128i* j0      = SM4_GCM_CONTEXT_J0(p_context);
    __m128i* hashkey = SM4_GCM_CONTEXT_HASHKEY(p_context)[0];

    int64u* iv_len = SM4_GCM_CONTEXT_LEN(p_context);

    __m512i hashkeys_4_0, hashkeys_4_1, hashkeys_4_2, hashkeys_4_3;
    __m512i* hashkeys[] = { &hashkeys_4_0, &hashkeys_4_1, &hashkeys_4_2, &hashkeys_4_3 };

    __m512i iv_blocks_4_0, iv_blocks_4_1, iv_blocks_4_2, iv_blocks_4_3;
    __m512i* data_blocks[] = { &iv_blocks_4_0, &iv_blocks_4_1, &iv_blocks_4_2, &iv_blocks_4_3 };

    __m512i len_hi = loadu(iv_len);
    __m512i len_lo = loadu(iv_len + 8);

    __mmask8 eq_12_mask_hi = cmp_epi64_mask(len_hi, set1_epi64(12), _MM_CMPINT_EQ);
    __mmask8 eq_12_mask_lo = cmp_epi64_mask(len_lo, set1_epi64(12), _MM_CMPINT_EQ);

    __mmask8 eq_0_mask_hi = cmp_epi64_mask(len_hi, setzero(), _MM_CMPINT_EQ);
    __mmask8 eq_0_mask_lo = cmp_epi64_mask(len_lo, setzero(), _MM_CMPINT_EQ);

    __mmask16 eq_12_mask = eq_12_mask_lo << 8 | eq_12_mask_hi;
    __mmask16 eq_0_mask  = eq_0_mask_lo << 8 | eq_0_mask_hi;

    __mmask16 load_mask = ~eq_12_mask | ~eq_0_mask;

    /* Finalize IVs of length != 96 bit */
    if (load_mask) {

        hashkeys_4_0 = loadu(hashkey + 0);
        hashkeys_4_1 = loadu(hashkey + 4);
        hashkeys_4_2 = loadu(hashkey + 8);
        hashkeys_4_3 = loadu(hashkey + 12);

        iv_blocks_4_0 = setzero();
        iv_blocks_4_1 = setzero();
        iv_blocks_4_2 = setzero();
        iv_blocks_4_3 = setzero();

        /*
      // Loop with 4 iterations here does not unrolled by some compilers
      // Unrolled explicitly because insert32x4 require the last parameter to be const
      */

        /* Begin of explicitly unrolled loop */
        __m128i input_block_0 = _mm_maskz_set1_epi64(1, *(iv_len + (0 + 4 * 0)) << 3);
        __m128i input_block_1 = _mm_maskz_set1_epi64(1, *(iv_len + (0 + 4 * 1)) << 3);
        __m128i input_block_2 = _mm_maskz_set1_epi64(1, *(iv_len + (0 + 4 * 2)) << 3);
        __m128i input_block_3 = _mm_maskz_set1_epi64(1, *(iv_len + (0 + 4 * 3)) << 3);

        iv_blocks_4_0 = insert32x4(iv_blocks_4_0, input_block_0, 0);
        iv_blocks_4_1 = insert32x4(iv_blocks_4_1, input_block_1, 0);
        iv_blocks_4_2 = insert32x4(iv_blocks_4_2, input_block_2, 0);
        iv_blocks_4_3 = insert32x4(iv_blocks_4_3, input_block_3, 0);

        input_block_0 = _mm_maskz_set1_epi64(1, *(iv_len + (1 + 4 * 0)) << 3);
        input_block_1 = _mm_maskz_set1_epi64(1, *(iv_len + (1 + 4 * 1)) << 3);
        input_block_2 = _mm_maskz_set1_epi64(1, *(iv_len + (1 + 4 * 2)) << 3);
        input_block_3 = _mm_maskz_set1_epi64(1, *(iv_len + (1 + 4 * 3)) << 3);

        iv_blocks_4_0 = insert32x4(iv_blocks_4_0, input_block_0, 1);
        iv_blocks_4_1 = insert32x4(iv_blocks_4_1, input_block_1, 1);
        iv_blocks_4_2 = insert32x4(iv_blocks_4_2, input_block_2, 1);
        iv_blocks_4_3 = insert32x4(iv_blocks_4_3, input_block_3, 1);

        input_block_0 = _mm_maskz_set1_epi64(1, *(iv_len + (2 + 4 * 0)) << 3);
        input_block_1 = _mm_maskz_set1_epi64(1, *(iv_len + (2 + 4 * 1)) << 3);
        input_block_2 = _mm_maskz_set1_epi64(1, *(iv_len + (2 + 4 * 2)) << 3);
        input_block_3 = _mm_maskz_set1_epi64(1, *(iv_len + (2 + 4 * 3)) << 3);

        iv_blocks_4_0 = insert32x4(iv_blocks_4_0, input_block_0, 2);
        iv_blocks_4_1 = insert32x4(iv_blocks_4_1, input_block_1, 2);
        iv_blocks_4_2 = insert32x4(iv_blocks_4_2, input_block_2, 2);
        iv_blocks_4_3 = insert32x4(iv_blocks_4_3, input_block_3, 2);

        input_block_0 = _mm_maskz_set1_epi64(1, *(iv_len + (3 + 4 * 0)) << 3);
        input_block_1 = _mm_maskz_set1_epi64(1, *(iv_len + (3 + 4 * 1)) << 3);
        input_block_2 = _mm_maskz_set1_epi64(1, *(iv_len + (3 + 4 * 2)) << 3);
        input_block_3 = _mm_maskz_set1_epi64(1, *(iv_len + (3 + 4 * 3)) << 3);

        iv_blocks_4_0 = insert32x4(iv_blocks_4_0, input_block_0, 3);
        iv_blocks_4_1 = insert32x4(iv_blocks_4_1, input_block_1, 3);
        iv_blocks_4_2 = insert32x4(iv_blocks_4_2, input_block_2, 3);
        iv_blocks_4_3 = insert32x4(iv_blocks_4_3, input_block_3, 3);

        /* End of explicitly unrolled loop */

        iv_blocks_4_0 = xor(iv_blocks_4_0, loadu(j0 + 0));
        iv_blocks_4_1 = xor(iv_blocks_4_1, loadu(j0 + 4));
        iv_blocks_4_2 = xor(iv_blocks_4_2, loadu(j0 + 8));
        iv_blocks_4_3 = xor(iv_blocks_4_3, loadu(j0 + 12));

        sm4_gcm_ghash_mul_single_block_mb16(data_blocks, hashkeys);

        iv_blocks_4_0 = shuffle_epi8(iv_blocks_4_0, M512(swapEndianness));
        iv_blocks_4_1 = shuffle_epi8(iv_blocks_4_1, M512(swapEndianness));
        iv_blocks_4_2 = shuffle_epi8(iv_blocks_4_2, M512(swapEndianness));
        iv_blocks_4_3 = shuffle_epi8(iv_blocks_4_3, M512(swapEndianness));

        __mmask8 store_mask_0 = 0x03 * (0x1 & ((load_mask >> 0 * 4) >> 0)) |
                                0x0C * (0x1 & ((load_mask >> 0 * 4) >> 1)) |
                                0x30 * (0x1 & ((load_mask >> 0 * 4) >> 2)) |
                                0xC0 * (0x1 & ((load_mask >> 0 * 4) >> 3));

        __mmask8 store_mask_1 = 0x03 * (0x1 & ((load_mask >> 1 * 4) >> 0)) |
                                0x0C * (0x1 & ((load_mask >> 1 * 4) >> 1)) |
                                0x30 * (0x1 & ((load_mask >> 1 * 4) >> 2)) |
                                0xC0 * (0x1 & ((load_mask >> 1 * 4) >> 3));

        __mmask8 store_mask_2 = 0x03 * (0x1 & ((load_mask >> 2 * 4) >> 0)) |
                                0x0C * (0x1 & ((load_mask >> 2 * 4) >> 1)) |
                                0x30 * (0x1 & ((load_mask >> 2 * 4) >> 2)) |
                                0xC0 * (0x1 & ((load_mask >> 2 * 4) >> 3));

        __mmask8 store_mask_3 = 0x03 * (0x1 & ((load_mask >> 3 * 4) >> 0)) |
                                0x0C * (0x1 & ((load_mask >> 3 * 4) >> 1)) |
                                0x30 * (0x1 & ((load_mask >> 3 * 4) >> 2)) |
                                0xC0 * (0x1 & ((load_mask >> 3 * 4) >> 3));

        mask_storeu_epi64(j0 + 0, store_mask_0, iv_blocks_4_0);
        mask_storeu_epi64(j0 + 4, store_mask_1, iv_blocks_4_1);
        mask_storeu_epi64(j0 + 8, store_mask_2, iv_blocks_4_2);
        mask_storeu_epi64(j0 + 12, store_mask_3, iv_blocks_4_3);
    }

    /* Finalize IVs of length == 96 bit */
    if (eq_12_mask != 0 && pa_iv != NULL) {
        __m128i iv_block;

        for (int i = 0; i < SM4_LINES; i++) {
            iv_block =
                _mm_mask_loadu_epi8(M128(one_f), 0x0FFF * (0x1 & eq_12_mask), (void*)pa_iv[i]);
            _mm_mask_storeu_epi8(j0 + i, 0xFFFF * (0x1 & eq_12_mask), iv_block);
            eq_12_mask >>= 1;
        }
    }

    /* Store initial counter */
    storeu(ctr + 0, inc_block32(shuffle_epi8(loadu(j0 + 0), M512(swapEndianness)), initialInc));
    storeu(ctr + 4, inc_block32(shuffle_epi8(loadu(j0 + 4), M512(swapEndianness)), initialInc));
    storeu(ctr + 8, inc_block32(shuffle_epi8(loadu(j0 + 8), M512(swapEndianness)), initialInc));
    storeu(ctr + 12, inc_block32(shuffle_epi8(loadu(j0 + 12), M512(swapEndianness)), initialInc));

    sm4_encrypt_j0_mb16(p_context);

    /* Clear length buffer to reuse it for TXT and AAD length */
    SM4_GCM_CLEAR_LEN(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 0));
    SM4_GCM_CLEAR_LEN(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 1));
    SM4_GCM_CLEAR_LEN(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 2));
    SM4_GCM_CLEAR_LEN(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 3));
}

#endif /* #if (_MBX>=_MBX_K1) */
