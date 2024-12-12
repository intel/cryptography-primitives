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
#include <internal/sm4/sm4_ccm_mb.h>
#include <internal/rsa/ifma_rsa_arith.h> /* for zero_mb8 */

#if (_MBX >= _MBX_K1)

static void sm4_encrypt_ctr0_mb16(SM4_CCM_CTX_mb16* p_context, __m512i* s0_blocks)
{
    const mbx_sm4_key_schedule* key_sched =
        (const mbx_sm4_key_schedule*)SM4_CCM_CONTEXT_KEY(p_context);

    __m128i* ctr0 = SM4_CCM_CONTEXT_CTR0(p_context);

    const int8u* pa_inp[SM4_LINES];

    for (int i = 0; i < SM4_LINES; i++)
        pa_inp[i] = (unsigned char*)(ctr0 + i);

    TRANSPOSE_16x4_I32_EPI32(
        &s0_blocks[0], &s0_blocks[1], &s0_blocks[2], &s0_blocks[3], pa_inp, 0xFFFF);

    const __m512i* p_rk = (const __m512i*)key_sched;

    __m512i tmp;
    for (int itr = 0; itr < SM4_ROUNDS; itr += 4, p_rk += 4)
        SM4_FOUR_ROUNDS(s0_blocks[0], s0_blocks[1], s0_blocks[2], s0_blocks[3], tmp, p_rk, 1);

    __m512i T1_0 = unpacklo_epi32(s0_blocks[0], s0_blocks[1]);
    __m512i T1_1 = unpackhi_epi32(s0_blocks[0], s0_blocks[1]);
    __m512i T1_2 = unpacklo_epi32(s0_blocks[2], s0_blocks[3]);
    __m512i T1_3 = unpackhi_epi32(s0_blocks[2], s0_blocks[3]);

    s0_blocks[0] = unpacklo_epi64(T1_0, T1_2);
    s0_blocks[1] = unpackhi_epi64(T1_0, T1_2);
    s0_blocks[2] = unpacklo_epi64(T1_1, T1_3);
    s0_blocks[3] = unpackhi_epi64(T1_1, T1_3);

    s0_blocks[0] = shuffle_epi8(s0_blocks[0], M512(swapEndianness));
    s0_blocks[1] = shuffle_epi8(s0_blocks[1], M512(swapEndianness));
    s0_blocks[2] = shuffle_epi8(s0_blocks[2], M512(swapEndianness));
    s0_blocks[3] = shuffle_epi8(s0_blocks[3], M512(swapEndianness));

    T1_0 = _mm512_shuffle_i64x2(s0_blocks[0], s0_blocks[1], 0x44);
    T1_1 = _mm512_shuffle_i64x2(s0_blocks[0], s0_blocks[1], 0xEE);
    T1_2 = _mm512_shuffle_i64x2(s0_blocks[2], s0_blocks[3], 0x44);
    T1_3 = _mm512_shuffle_i64x2(s0_blocks[2], s0_blocks[3], 0xEE);

    s0_blocks[0] = _mm512_shuffle_i64x2(T1_0, T1_2, 0x88);
    s0_blocks[1] = _mm512_shuffle_i64x2(T1_0, T1_2, 0xDD);
    s0_blocks[2] = _mm512_shuffle_i64x2(T1_1, T1_3, 0x88);
    s0_blocks[3] = _mm512_shuffle_i64x2(T1_1, T1_3, 0xDD);
}

mbx_status16 sm4_ccm_get_tag_mb16(int8u* pa_out[SM4_LINES],
                                  const int tag_len[SM4_LINES],
                                  __mmask16 mb_mask,
                                  SM4_CCM_CTX_mb16* p_context)
{
    mbx_status16 status = 0;
    __m512i s0_blocks[4];
    __m512i hash_blocks[4];

    __m128i* hash = SM4_CCM_CONTEXT_HASH(p_context);

    /* Calculate S0 */
    sm4_encrypt_ctr0_mb16(p_context, s0_blocks);

    hash_blocks[0] = loadu(hash);
    hash_blocks[1] = loadu(hash + 4);
    hash_blocks[2] = loadu(hash + 4 * 2);
    hash_blocks[3] = loadu(hash + 4 * 3);

    __m512i tag_blocks[4];

    /* XOR with previously encrypted J0 */
    tag_blocks[0] = xor(hash_blocks[0], s0_blocks[0]);
    tag_blocks[1] = xor(hash_blocks[1], s0_blocks[1]);
    tag_blocks[2] = xor(hash_blocks[2], s0_blocks[2]);
    tag_blocks[3] = xor(hash_blocks[3], s0_blocks[3]);

    /* Store result */
    for (int i = 0; i < SM4_LINES; i++) {
        __m128i one_block = M128((__m128i*)tag_blocks + i);

        __mmask16 tagMask = ~(0xFFFF << (tag_len[i])) * ((mb_mask >> i) & 0x1);
        _mm_mask_storeu_epi8((void*)(pa_out[i]), tagMask, one_block);
    }

    /* Clear local copy of sensitive data */
    zero_mb8((int64u(*)[8])tag_blocks, sizeof(tag_blocks) / sizeof(tag_blocks[0]));
    zero_mb8((int64u(*)[8])hash_blocks, sizeof(hash_blocks) / sizeof(hash_blocks[0]));
    zero_mb8((int64u(*)[8])s0_blocks, sizeof(s0_blocks) / sizeof(s0_blocks[0]));

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
