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
// This function performs decryption of given data and updates ghash with given data.
// Function returns mask where bit is set to 1 if length of given data for buffer is overflowed.
*/

__mmask16 sm4_gcm_decrypt_mb16(int8u* pa_out[SM4_LINES],
                               const int8u* const pa_in[SM4_LINES],
                               const int in_len[SM4_LINES],
                               __mmask16 mb_mask,
                               SM4_GCM_CTX_mb16* p_context)
{
    if (SM4_GCM_CONTEXT_STATE(p_context) == sm4_gcm_update_iv) {
        /* Finalize IVs */
        sm4_gcm_finalize_iv_mb16(NULL, mb_mask, p_context);
    }

    /* Switch context state to decryption */
    SM4_GCM_CONTEXT_STATE(p_context) = sm4_gcm_dec;

    const int8u* loc_pa_in[SM4_LINES];
    int in_len_rearranged[SM4_LINES];

    /* Rearrange input pointers and lengths to required layout */
    rearrange(loc_pa_in, pa_in);
    rearrange(in_len_rearranged, in_len);
    __m512i loc_in_len = loadu(in_len_rearranged);

    __mmask16 overflow_mask = 0x0000;
    __m512i max_txt_len     = set1_epi64(0xFFFFFFFE0); /* (2^39 - 256) div 8 */

    /*
   // Update txt length
   //
   // TXT length is passed as 32 bit integer
   // TXT length is used to construct last block for ghash computation as follow:
   // 64 bits with AAD length | 64 bits with TXT length
   // Length of AAD and TXT is stored in context in this form
   //
   // Code below transforms 32 bit input integers into the following block:
   // 64 bits with TXT length | 64 zero bits
   // and add it to length stored in context
   //
   // The whole operation is the following for each buffer:
   // 64 bits with AAD len in context | 64 bits with TXT len in context
   // +
   // 64 zero bits                    | 32 zero bits | 32 bits with input TXT len
   */

    for (int i = 0; i < 4; i++) {
        __m512i len_updade = maskz_expandloadu_epi32(
            0x1111, (void*)(in_len_rearranged + i * 4)); /* Load txt len to high part of registry */
        __m512i len_context = loadu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), i));

        len_context = add_epi64(len_context, len_updade);

        storeu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), i), len_context);

        __mmask8 overflow_mask_part = cmp_epi64_mask(max_txt_len, len_context, _MM_CMPINT_LE);

        overflow_mask_part = (overflow_mask_part & 0x01) | (overflow_mask_part & 0x04) >> 1 |
                             (overflow_mask_part & 0x10) >> 2 | (overflow_mask_part & 0x40) >> 3;
        overflow_mask = overflow_mask | overflow_mask_part << (i * 4);
    }

    /* Update intermediate ghash value with full blocks of given data */
    sm4_gcm_update_ghash_full_blocks_mb16(SM4_GCM_CONTEXT_GHASH(p_context),
                                          loc_pa_in,
                                          &loc_in_len,
                                          SM4_GCM_CONTEXT_HASHKEY(p_context),
                                          mb_mask);

    if (cmp_epi32_mask(loc_in_len, setzero(), _MM_CMPINT_EQ) != 0xFFFF) {
        /* Update intermediate ghash value with partial blocks of given data */
        sm4_gcm_update_ghash_partial_blocks_mb16(SM4_GCM_CONTEXT_GHASH(p_context),
                                                 loc_pa_in,
                                                 &loc_in_len,
                                                 SM4_GCM_CONTEXT_HASHKEY(p_context)[0],
                                                 mb_mask);
        /* Switch context state to tag computation to prevent decryption after any partial blocks are processed */
        SM4_GCM_CONTEXT_STATE(p_context) = sm4_gcm_get_tag;
    }

    const mbx_sm4_key_schedule* key_sched =
        (const mbx_sm4_key_schedule*)SM4_GCM_CONTEXT_KEY(p_context);

    /* Decrypt */
    sm4_gctr_kernel_mb16(pa_out, pa_in, in_len, (const int32u**)key_sched, mb_mask, p_context);

    return overflow_mask;
}

#endif /* #if (_MBX>=_MBX_K1) */
