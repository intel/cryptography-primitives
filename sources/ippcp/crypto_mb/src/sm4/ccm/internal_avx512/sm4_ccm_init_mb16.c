/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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

mbx_status16 internal_avx512_sm4_ccm_init_mb16(const sm4_key* const pa_key[SM4_LINES],
                                               const int8u* const pa_iv[SM4_LINES],
                                               const int iv_len[SM4_LINES],
                                               const int tag_len[SM4_LINES],
                                               const int64u msg_len[SM4_LINES],
                                               SM4_CCM_CTX_mb16* p_context,
                                               __mmask16 mb_mask)
{
    mbx_status16 status = 0;

    /*
    // Compute SM4 keys
    // initialize int32u mbx_sm4_key_schedule[SM4_ROUNDS][SM4_LINES] buffer in context
    // keys layout for each round:
    // key0 key4 key8 key12 key1 key5 key9 key13 key2 key6 key10 key14 key3 key7 key11 key15
    */

    internal_avx512_sm4_set_round_keys_mb16(
        (int32u**)SM4_CCM_CONTEXT_KEY(p_context), (const int8u**)pa_key, mb_mask);

    /* Process IV */
    sm4_ccm_update_iv_mb16(pa_iv, iv_len, mb_mask, p_context);

    /* Zero initial msg and tag lengths */
    PadBlock(0, SM4_CCM_CONTEXT_MSG_LEN(p_context), sizeof(int64u) * SM4_LINES);
    PadBlock(0, SM4_CCM_CONTEXT_PROCESSED_LEN(p_context), sizeof(int64u) * SM4_LINES);
    PadBlock(0, SM4_CCM_CONTEXT_TAG_LEN(p_context), sizeof(int) * SM4_LINES);

    /* Process msg and tag lengths */
    sm4_ccm_set_msg_len_mb16(msg_len, mb_mask, p_context);

    sm4_ccm_set_tag_len_mb16(tag_len, mb_mask, p_context);

    /* Zero initial hash values */
    PadBlock(0, SM4_CCM_CONTEXT_HASH(p_context), 16 * SM4_LINES);

    SM4_CCM_CONTEXT_STATE(p_context) = sm4_ccm_update_aad;

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
