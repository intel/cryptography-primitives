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
// This function process 16 buffers with initialization vector (IV) data
*/
__mmask16 sm4_gcm_update_iv_mb16(const int8u* const pa_iv[SM4_LINES],
                                 const int iv_len[SM4_LINES],
                                 __mmask16 mb_mask,
                                 SM4_GCM_CTX_mb16* p_context)
{
    SM4_GCM_CONTEXT_STATE(p_context) = sm4_gcm_update_iv;

    __m128i* j0 = SM4_GCM_CONTEXT_J0(p_context);

    const int8u* loc_pa_iv[SM4_LINES];
    int iv_len_rearranged[SM4_LINES];

    /* Rearrange pointers and lengths to right layout */
    rearrange(loc_pa_iv, pa_iv);
    rearrange(iv_len_rearranged, iv_len);

    __m512i loc_iv_len = loadu(iv_len_rearranged);
    __m512i max_iv_len = set1_epi64(0x1FFFFFFFFFFFFFFF); /* (2^64 - 1) div 8 */

    /*
   // Update full IV length
   //
   // IV length is passed as 32 bit integer
   // IV length is used to construct last block for ghash computation as follow:
   // 64 zero bits | 64 IV len bits
   // Length of IV is stored in context in 64 bits
   //
   // Code below transforms 32 bit input integers into the following block:
   // 32 zero bits | 32 IV len bits
   // and add it to length stored in context
   //
   // The whole operation is following for each buffer:
   // 64 bits with IV len in context
   // +
   // 32 zero bits | 32 bits with input IV len
   //
   // Last J0 block is constructed in IV finalization
   */

    __m512i full_iv_len = maskz_expandloadu_epi32(0x5555, iv_len_rearranged);
    full_iv_len = add_epi64(full_iv_len, loadu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 0)));
    storeu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 0), full_iv_len);

    __mmask8 mask_overflow_lo = cmp_epi64_mask(max_iv_len, full_iv_len, _MM_CMPINT_LT);

    full_iv_len = maskz_expandloadu_epi32(0x5555, iv_len_rearranged + 8);
    full_iv_len = add_epi64(full_iv_len, loadu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 1)));
    storeu(BUFFER_REG_NUM(SM4_GCM_CONTEXT_LEN(p_context), 1), full_iv_len);

    __mmask8 mask_overflow_hi = cmp_epi64_mask(max_iv_len, full_iv_len, _MM_CMPINT_LT);

    __mmask16 mask_overflow = mask_overflow_hi << 8 | mask_overflow_lo;

    /* Process full blocks of IVs */
    sm4_gcm_update_ghash_full_blocks_mb16(
        j0, loc_pa_iv, &loc_iv_len, SM4_GCM_CONTEXT_HASHKEY(p_context), mb_mask);

    if (cmp_epi32_mask(loc_iv_len, setzero(), _MM_CMPINT_EQ) != 0xFFFF) {
        /* Process partial blocks of IVs and finalize IVs */
        sm4_gcm_update_ghash_partial_blocks_mb16(
            j0, loc_pa_iv, &loc_iv_len, SM4_GCM_CONTEXT_HASHKEY(p_context)[0], mb_mask);
        sm4_gcm_finalize_iv_mb16(loc_pa_iv, mb_mask, p_context);

        SM4_GCM_CONTEXT_STATE(p_context) = sm4_gcm_update_aad;
    }

    return mask_overflow;
}

#endif /* #if (_MBX>=_MBX_K1) */
