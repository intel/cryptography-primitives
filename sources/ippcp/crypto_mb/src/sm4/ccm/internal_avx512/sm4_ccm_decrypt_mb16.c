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

/*
 * This function performs decryption with CTR and then authentication with CBC-MAC on plaintext.
 * Function returns mask where bit is set to 1 if length of given data for buffer is overflowed.
*/

mbx_status16 sm4_ccm_decrypt_mb16(int8u* pa_out[SM4_LINES],
                                  const int8u* const pa_in[SM4_LINES],
                                  const int in_len[SM4_LINES],
                                  __mmask16 mb_mask,
                                  SM4_CCM_CTX_mb16* p_context)
{
    mbx_status16 status = 0;
    __m128i* hash       = SM4_CCM_CONTEXT_HASH(p_context);
    __m128i* ctr        = SM4_CCM_CONTEXT_CTR(p_context);

    const int8u* hash_ptrs[SM4_LINES];
    int8u* pa_ctr[SM4_LINES];
    unsigned i;
    int full_hash_len[SM4_LINES];
    int partial_hash_len[SM4_LINES];
    int8u padded_hash[SM4_LINES][SM4_BLOCK_SIZE];
    int8u* pa_padded_hash[SM4_LINES];
    __mmask16 partial_block_mask = 0;

    /* No AAD processed */
    if (SM4_CCM_CONTEXT_STATE(p_context) == sm4_ccm_update_aad) {
        int aad_lens[SM4_LINES];

        PadBlock(0, aad_lens, sizeof(aad_lens));
        sm4_ccm_update_aad_mb16(NULL, aad_lens, 0xFFFF, p_context);
    }

    /* Switch context state to decryption */
    SM4_CCM_CONTEXT_STATE(p_context) = sm4_ccm_dec;

    for (i = 0; i < SM4_LINES; i++) {
        hash_ptrs[i]     = (int8u*)&hash[i];
        pa_ctr[i]        = (int8u*)&ctr[i];
        full_hash_len[i] = in_len[i] & 0xFFFFFFF0;
    }

    /* Decrypt first */
    sm4_ctr128_kernel_mb16(pa_out,
                           (const int8u**)pa_in,
                           in_len,
                           (const int32u**)SM4_CCM_CONTEXT_KEY(p_context),
                           mb_mask,
                           pa_ctr);

    /* Authenticate the plaintext */
    sm4_cbc_mac_kernel_mb16(hash,
                            (const int8u* const*)pa_out,
                            full_hash_len,
                            (const int32u**)SM4_CCM_CONTEXT_KEY(p_context),
                            mb_mask,
                            hash_ptrs);

    /* Handle partial blocks of plaintext */
    for (i = 0; i < SM4_LINES; i++) {
        partial_hash_len[i] = in_len[i] & 0xF;
        if (partial_hash_len[i] == 0)
            continue;
        pa_padded_hash[i] = padded_hash[i];
        PadBlock(0, pa_padded_hash[i], SM4_BLOCK_SIZE);
        CopyBlock(pa_out[i] + full_hash_len[i], pa_padded_hash[i], partial_hash_len[i]);
        full_hash_len[i] = SM4_BLOCK_SIZE;
        partial_block_mask |= (1 << i);
    }
    if (partial_block_mask != 0) {
        sm4_cbc_mac_kernel_mb16(hash,
                                (const int8u* const*)pa_padded_hash,
                                full_hash_len,
                                (const int32u**)SM4_CCM_CONTEXT_KEY(p_context),
                                partial_block_mask,
                                hash_ptrs);
        SM4_CCM_CONTEXT_STATE(p_context) = sm4_ccm_get_tag;
    }

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
