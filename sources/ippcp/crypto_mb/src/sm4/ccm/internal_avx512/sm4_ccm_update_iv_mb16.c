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

#include <internal/sm4/sm4_ccm_mb.h>
#include <internal/common/mem_fns.h>

#if (_MBX >= _MBX_K1)

/*
// This function process 16 buffers with initialization vector (IV) data
*/
void sm4_ccm_update_iv_mb16(const int8u* const pa_iv[SM4_LINES],
                            const int iv_len[SM4_LINES],
                            __mmask16 mb_mask,
                            SM4_CCM_CTX_mb16* p_context)
{
    int* iv_len_ctx = SM4_CCM_CONTEXT_IV_LEN(p_context);
    __m128i* ctr0   = SM4_CCM_CONTEXT_CTR0(p_context);
    __m128i* ctr    = SM4_CCM_CONTEXT_CTR(p_context);

    unsigned i;

    for (i = 0; i < SM4_LINES; i++) {
        if (mb_mask & (1 << i)) {
            int8u flags;
            unsigned L;
            int iv_len_i = iv_len[i];

            L     = 15 - iv_len_i;
            flags = L - 1;
            /* Update CTR0 for each lane */
            int8u* ctr0_nonce_ptr = (int8u*)&(ctr0[i]);
            PadBlock(0, ctr0_nonce_ptr, 16);
            CopyBlock(pa_iv[i], ctr0_nonce_ptr + 1, iv_len_i);
            ctr0_nonce_ptr[0] = flags;

            /* Update CTR for each lane (counter = 1 to start encryption) */
            int8u* ctr_nonce_ptr = (int8u*)&(ctr[i]);
            PadBlock(0, ctr_nonce_ptr, 16);
            CopyBlock(pa_iv[i], ctr_nonce_ptr + 1, iv_len_i);
            ctr_nonce_ptr[0]  = flags;
            ctr_nonce_ptr[15] = 1;
            iv_len_ctx[i]     = iv_len[i];
        }
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
