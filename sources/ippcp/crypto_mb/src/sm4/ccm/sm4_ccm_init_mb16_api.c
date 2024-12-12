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

DLL_PUBLIC
mbx_status16 OWNAPI(mbx_sm4_ccm_init_mb16)(const sm4_key* const pa_key[SM4_LINES],
                                           const int8u* const pa_iv[SM4_LINES],
                                           const int iv_len[SM4_LINES],
                                           const int tag_len[SM4_LINES],
                                           const int64u msg_len[SM4_LINES],
                                           SM4_CCM_CTX_mb16* p_context)
{
    int buf_no;
    mbx_status16 status = 0;
    int16u mb_mask      = 0xFFFF;

    /* Test input pointers */
    if (NULL == pa_key || NULL == pa_iv || NULL == iv_len || NULL == tag_len || NULL == msg_len ||
        NULL == p_context) {
        status = MBX_SET_STS16_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* Don't process buffers with input pointers equal to zero and set bad status for IV with zero length */
    for (buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        if (pa_key[buf_no] == NULL) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
            mb_mask &= ~(0x1 << buf_no);
            continue;
        }
        if (pa_iv[buf_no] == NULL) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
            mb_mask &= ~(0x1 << buf_no);
            continue;
        }
        if ((iv_len[buf_no] < MIN_CCM_IV_LENGTH || iv_len[buf_no] > MAX_CCM_IV_LENGTH)) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
            mb_mask &= ~(0x1 << buf_no);
            continue;
        }
        if ((tag_len[buf_no] < MIN_CCM_TAG_LENGTH) || (tag_len[buf_no] > MAX_CCM_TAG_LENGTH) ||
            (tag_len[buf_no] & 0x1)) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
            mb_mask &= ~(0x1 << buf_no);
            continue;
        }

        /* Check maximum message length allowed, given the number of bytes to encode message length */
        int q = 15 - iv_len[buf_no];
        int64u max_len =
            (q == 8) ? 0xFFFFFFFFFFFFFFFF : ((1ULL << (q << 3)) - 1); /* (2^(q * 8) - 1 */

        if (msg_len[buf_no] > max_len) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
            mb_mask &= ~(0x1 << buf_no);
        }
    }

#if (_MBX >= _MBX_K1)
    if (MBX_IS_ANY_OK_STS16(status))
        status |= internal_avx512_sm4_ccm_init_mb16(
            pa_key, pa_iv, iv_len, tag_len, msg_len, p_context, (__mmask16)mb_mask);
#else
    MBX_UNREFERENCED_PARAMETER(mb_mask);
    status = MBX_SET_STS16_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
