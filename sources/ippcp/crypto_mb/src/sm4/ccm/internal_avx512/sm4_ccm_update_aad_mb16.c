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
#include <internal/common/mem_fns.h>

#if (_MBX >= _MBX_K1)

#define MAX_AAD_SIZE_BLOCKS_0_3 46
/*
 * This function process 16 buffers with additional authentication data (AAD),
 * up to 2^16 - 2^8 bytes
*/

mbx_status16 sm4_ccm_update_aad_mb16(const int8u* const pa_aad[SM4_LINES],
                                     const int aad_len[SM4_LINES],
                                     __mmask16 mb_mask,
                                     SM4_CCM_CTX_mb16* p_context)
{
    mbx_status16 status = 0;
    __m128i* ctr0       = SM4_CCM_CONTEXT_CTR0(p_context);
    int* tag_len        = SM4_CCM_CONTEXT_TAG_LEN(p_context);
    int* iv_len         = SM4_CCM_CONTEXT_IV_LEN(p_context);
    int64u* msg_len     = SM4_CCM_CONTEXT_MSG_LEN(p_context);
    __m128i* hash       = SM4_CCM_CONTEXT_HASH(p_context);
    /* Scratch memory to construct up to 4 blocks to authenticate (up to 46 byte of AAD) */
    int8u tmp[SM4_LINES][SM4_BLOCK_SIZE * 4];
    const int8u* block_ptrs[SM4_LINES];
    const int8u* hash_ptrs[SM4_LINES];
    int auth_lens[SM4_LINES];
    unsigned i, j;
    int8u iv[SM4_LINES][SM4_BLOCK_SIZE];
    const int8u* iv_ptrs[SM4_LINES];
    int additional_lens[SM4_LINES];

    __m512i max_msg16b_len = set1_epi64(0xFFFF);
    __mmask16 additional_len_mask =
        _mm512_cmp_epi32_mask(set1_epi32(MAX_AAD_SIZE_BLOCKS_0_3), loadu(aad_len), _MM_CMPINT_LT);
    __mmask8 msg_len_overflow_lo_mask =
        _mm512_cmp_epi64_mask(max_msg16b_len, loadu(msg_len), _MM_CMPINT_LE);
    __mmask8 msg_len_overflow_hi_mask =
        _mm512_cmp_epi64_mask(max_msg16b_len, loadu(msg_len + 8), _MM_CMPINT_LE);
    __mmask16 msg_len_overflow_mask =
        (__mmask16)msg_len_overflow_hi_mask << 8 | (__mmask16)msg_len_overflow_lo_mask;

    additional_len_mask = _mm512_kand(additional_len_mask, mb_mask);

    PadBlock(0, tmp, sizeof(tmp));
    PadBlock(0, iv, sizeof(iv));

    for (i = 0; i < SM4_LINES; i++) {

        additional_lens[i] = 0;

        if ((mb_mask & (1 << i)) == 0) {
            auth_lens[i]  = 0;
            block_ptrs[i] = NULL;
            hash_ptrs[i]  = NULL;
            iv_ptrs[i]    = NULL;
            continue;
        }

        CopyBlock(&ctr0[i], tmp[i], SM4_BLOCK_SIZE);

        int8u flags = tmp[i][0];

        int8u tag_len_enc = (tag_len[i] - 2) >> 1;

        flags |= (tag_len_enc) << 3;
        auth_lens[i]  = SM4_BLOCK_SIZE;
        block_ptrs[i] = tmp[i];
        hash_ptrs[i]  = (int8u*)&hash[i];
        iv_ptrs[i]    = iv[i];
        if (aad_len[i]) {
            int len;

            if (aad_len[i] > MAX_AAD_SIZE_BLOCKS_0_3) {
                len                = MAX_AAD_SIZE_BLOCKS_0_3;
                additional_lens[i] = aad_len[i] - MAX_AAD_SIZE_BLOCKS_0_3;
            } else
                len = aad_len[i];
            flags |= 1 << 6;
            /* Copy AAD length to first 2 bytes of B_1 */
            tmp[i][16] = (int8u)(aad_len[i] >> 8);
            tmp[i][17] = (int8u)aad_len[i];
            /* Copy AAD afterwards */
            CopyBlock(pa_aad[i], &tmp[i][18], len);
            auth_lens[i] += (2 + 15 + len);
            auth_lens[i] &= 0xfff0; /* Multiple of 16 bytes */
        }
        tmp[i][0]  = flags;
        tmp[i][15] = (int8u)msg_len[i];
        tmp[i][14] = (int8u)(msg_len[i] >> 8);
    }

    /* Check if message is longer than 2^16 - 1 and set the length appropriately in block 0 */
    if (msg_len_overflow_mask) {
        for (i = 0; i < SM4_LINES; i++) {
            const unsigned num_bits_msg_len = 15 - iv_len[i];
            const int64u max_len =
                (num_bits_msg_len == 8) ? 0xFFFFFFFFFFFFFFFF : (1ULL << (num_bits_msg_len << 3));

            if (msg_len[i] < max_len) {
                for (j = 2; j < num_bits_msg_len; j++)
                    tmp[i][15 - j] = (int8u)(msg_len[i] >> (8 * j));
            }
        }
    }
    sm4_cbc_mac_kernel_mb16(hash,
                            (const int8u* const*)block_ptrs,
                            auth_lens,
                            (const int32u**)SM4_CCM_CONTEXT_KEY(p_context),
                            mb_mask,
                            iv_ptrs);

    /* More AAD to process */
    if (additional_len_mask) {
        for (i = 0; i < SM4_LINES; i++) {
            if (additional_lens[i]) {
                block_ptrs[i] =
                    pa_aad[i] + MAX_AAD_SIZE_BLOCKS_0_3;    /* First 46 bytes have been processed */
                auth_lens[i] = additional_lens[i] & 0xfff0; /* Multiple of 16 bytes */
                additional_lens[i] -= auth_lens[i];
                if (auth_lens[i] == 0)
                    additional_len_mask &= ~(1 << i);
            }
        }

        sm4_cbc_mac_kernel_mb16(hash,
                                (const int8u* const*)block_ptrs,
                                auth_lens,
                                (const int32u**)SM4_CCM_CONTEXT_KEY(p_context),
                                additional_len_mask,
                                hash_ptrs);

        additional_len_mask =
            _mm512_cmp_epi32_mask(set1_epi32(0), loadu(additional_lens), _MM_CMPINT_NE);
        /* Process last blocks (up to 15 bytes) */
        for (i = 0; i < SM4_LINES; i++) {
            if (additional_lens[i]) {
                block_ptrs[i] = tmp[i]; /* First 46 bytes have been processed */
                PadBlock(0, tmp[i], SM4_BLOCK_SIZE);
                CopyBlock(
                    pa_aad[i] + MAX_AAD_SIZE_BLOCKS_0_3 + auth_lens[i], tmp[i], additional_lens[i]);
                auth_lens[i] = SM4_BLOCK_SIZE;
            }
        }
        sm4_cbc_mac_kernel_mb16(hash,
                                (const int8u* const*)block_ptrs,
                                auth_lens,
                                (const int32u**)SM4_CCM_CONTEXT_KEY(p_context),
                                additional_len_mask,
                                hash_ptrs);
    }

    if (cmp_epi32_mask(loadu(aad_len), setzero(), _MM_CMPINT_EQ) != 0xFFFF)
        SM4_CCM_CONTEXT_STATE(p_context) = sm4_ccm_start_encdec;

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
