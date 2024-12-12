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
// This function performs tag computation as follow:
// v = 128 * [bitlen(AAD) / 128] - bitlen(AAD)
// u = 128 * [bitlen(TXT) / 128] - bitlen(TXT)
// S = GHASH (AAD || 0^v || ciphTXT || 0^u || bitlen(AAD) || bitlen(ciphTXT)).
// tag = S xor J0
//
// J0 is previously encrypted
//
// 0^s means the bit string that consists of s '0' bits here
// [x] means the least integer that is not less than the real number x here
*/

mbx_status16 sm4_gcm_get_tag_mb16(int8u* pa_out[SM4_LINES],
                                  const int tag_len[SM4_LINES],
                                  __mmask16 mb_mask,
                                  SM4_GCM_CTX_mb16* p_context)
{
    mbx_status16 status = 0;
    __m512i hashkeys_4_0, hashkeys_4_1, hashkeys_4_2, hashkeys_4_3;
    __m512i* hashkeys[] = { &hashkeys_4_0, &hashkeys_4_1, &hashkeys_4_2, &hashkeys_4_3 };

    __m512i data_len_blocks_4_0, data_len_blocks_4_1, data_len_blocks_4_2, data_len_blocks_4_3;
    __m512i* data_blocks[] = {
        &data_len_blocks_4_0, &data_len_blocks_4_1, &data_len_blocks_4_2, &data_len_blocks_4_3
    };

    __m128i* hashkey = SM4_GCM_CONTEXT_HASHKEY(p_context)[0];
    hashkeys_4_0     = loadu(hashkey + 0);
    hashkeys_4_1     = loadu(hashkey + 4);
    hashkeys_4_2     = loadu(hashkey + 8);
    hashkeys_4_3     = loadu(hashkey + 12);

    /* Convert length in bytes to length in bits */
    data_len_blocks_4_0 = sll_epi32(loadu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 0)),
                                    M128(bytes_to_bits_shift));
    data_len_blocks_4_1 = sll_epi32(loadu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 1)),
                                    M128(bytes_to_bits_shift));
    data_len_blocks_4_2 = sll_epi32(loadu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 2)),
                                    M128(bytes_to_bits_shift));
    data_len_blocks_4_3 = sll_epi32(loadu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 3)),
                                    M128(bytes_to_bits_shift));

    /* XOR with accumulated GHASH value */
    __m128i* ghash = SM4_GCM_CONTEXT_GHASH(p_context);

    data_len_blocks_4_0 = xor(data_len_blocks_4_0, loadu(ghash + 0));
    data_len_blocks_4_1 = xor(data_len_blocks_4_1, loadu(ghash + 4));
    data_len_blocks_4_2 = xor(data_len_blocks_4_2, loadu(ghash + 8));
    data_len_blocks_4_3 = xor(data_len_blocks_4_3, loadu(ghash + 12));

    /* Update GHASH value */
    sm4_gcm_ghash_mul_single_block_mb16(data_blocks, hashkeys);

    data_len_blocks_4_0 = shuffle_epi8(data_len_blocks_4_0, M512(swapEndianness));
    data_len_blocks_4_1 = shuffle_epi8(data_len_blocks_4_1, M512(swapEndianness));
    data_len_blocks_4_2 = shuffle_epi8(data_len_blocks_4_2, M512(swapEndianness));
    data_len_blocks_4_3 = shuffle_epi8(data_len_blocks_4_3, M512(swapEndianness));

    __m512i j0_blocks[4];

    __m128i* j0 = SM4_GCM_CONTEXT_J0(p_context);

    j0_blocks[0] = loadu(j0 + 0);
    j0_blocks[1] = loadu(j0 + 4);
    j0_blocks[2] = loadu(j0 + 8);
    j0_blocks[3] = loadu(j0 + 12);

    __m512i tag_blocks[4];

    /* XOR with previously encrypted J0 */
    tag_blocks[0] = xor(data_len_blocks_4_0, j0_blocks[0]);
    tag_blocks[1] = xor(data_len_blocks_4_1, j0_blocks[1]);
    tag_blocks[2] = xor(data_len_blocks_4_2, j0_blocks[2]);
    tag_blocks[3] = xor(data_len_blocks_4_3, j0_blocks[3]);

    /* Store result */
    for (int i = 0; i < SM4_LINES; i++) {
        __m128i one_block = M128((__m128i*)tag_blocks + i);

        __mmask16 tagMask = ~(0xFFFF << (tag_len[rearrangeOrder[i]])) * ((mb_mask >> i) & 0x1);
        _mm_mask_storeu_epi8((void*)(pa_out[rearrangeOrder[i]]), tagMask, one_block);
    }

    /* clear local copy of sensitive data */
    zero_mb8((int64u(*)[8])tag_blocks, sizeof(tag_blocks) / sizeof(tag_blocks[0]));

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
