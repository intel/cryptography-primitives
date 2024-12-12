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
// This function process 16 buffers with additional authentication data (AAD)
*/

__mmask16 sm4_gcm_update_aad_mb16(const int8u* const pa_aad[SM4_LINES],
                                  const int aad_len[SM4_LINES],
                                  __mmask16 mb_mask,
                                  SM4_GCM_CTX_mb16* p_context)
{
    if (SM4_GCM_CONTEXT_STATE(p_context) == sm4_gcm_update_iv) {
        /* Finalize IVs */
        sm4_gcm_finalize_iv_mb16(NULL, mb_mask, p_context);

        SM4_GCM_CONTEXT_STATE(p_context) = sm4_gcm_update_aad;
    }

    __m128i* ghash = SM4_GCM_CONTEXT_GHASH(p_context);

    const int8u* loc_pa_aad[SM4_LINES];
    int aad_len_rearranged[SM4_LINES];

    /* Rearrange pointers and lengths to right layout */
    rearrange(loc_pa_aad, pa_aad);
    rearrange(aad_len_rearranged, aad_len);

    __m512i loc_aad_len = loadu(aad_len_rearranged);

    __mmask16 overflow_mask = 0x0000;
    __m512i max_aad_len     = set1_epi64(0x1FFFFFFFFFFFFFFF); /* (2^64 - 1) div 8 */

    /*
   // Update aad len
   //
   // AAD length is passed as 32 bit integer
   // AAD length is used to construct last block for ghahs computation as follow:
   // 64 bits with AAD length | 64 bits with TXT length
   // Length of AAD and TXT is stored in context in this form
   //
   // Code below transforms 32 bit input integers into the following block:
   // 64 bits with AAD length | 64 zero bits
   // and add it to length stored in context
   //
   // The whole operation is the following for each buffer:
   // 64 bits with AAD len in context           | 64 bits with TXT len in context
   // +
   // 32 zero bits | 32 bits with input AAD len | 64 zero bits
   */

    for (int i = 0; i < 4; i++) {
        __m512i len_updade = maskz_expandloadu_epi32(
            0x4444,
            (void*)(aad_len_rearranged + i * 4)); /* Load aad len to low part of _m512iistry */
        __m512i len_context = loadu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), i));

        len_context = add_epi64(len_context, len_updade);
        storeu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), i), len_context);

        __mmask8 overflow_mask_part = cmp_epi64_mask(max_aad_len, len_context, _MM_CMPINT_LT);

        overflow_mask_part = (overflow_mask_part & 0x02) >> 1 | (overflow_mask_part & 0x08) >> 2 |
                             (overflow_mask_part & 0x20) >> 3 | (overflow_mask_part & 0x80) >> 4;
        overflow_mask = overflow_mask | overflow_mask_part << (i * 4);
    }

    /* Process full blocks of AADs */
    sm4_gcm_update_ghash_full_blocks_mb16(
        ghash, loc_pa_aad, &loc_aad_len, SM4_GCM_CONTEXT_HASHKEY(p_context), mb_mask);

    if (cmp_epi32_mask(loc_aad_len, setzero(), _MM_CMPINT_EQ) != 0xFFFF) {
        /* Process partial blocks of AADs */
        sm4_gcm_update_ghash_partial_blocks_mb16(
            ghash, loc_pa_aad, &loc_aad_len, SM4_GCM_CONTEXT_HASHKEY(p_context)[0], mb_mask);
        SM4_GCM_CONTEXT_STATE(p_context) = sm4_gcm_start_encdec;
    }

    return overflow_mask;
}

#endif /* #if (_MBX>=_MBX_K1) */
