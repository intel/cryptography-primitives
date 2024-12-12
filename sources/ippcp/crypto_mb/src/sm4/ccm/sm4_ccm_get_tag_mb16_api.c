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

DLL_PUBLIC
mbx_status16 OWNAPI(mbx_sm4_ccm_get_tag_mb16)(int8u* pa_tag[SM4_LINES],
                                              const int tag_len[SM4_LINES],
                                              SM4_CCM_CTX_mb16* p_context)
{
    int buf_no;
    mbx_status16 status   = 0;
    int16u mb_mask        = 0xFFFF;
    int64u* processed_len = SM4_CCM_CONTEXT_PROCESSED_LEN(p_context);
    int64u* msg_len       = SM4_CCM_CONTEXT_MSG_LEN(p_context);

    /* Test input pointers */
    if (NULL == pa_tag || NULL == tag_len || NULL == p_context) {
        status = MBX_SET_STS16_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* Check state */
    if (sm4_ccm_update_aad != SM4_CCM_CONTEXT_STATE(p_context) &&
        sm4_ccm_start_encdec != SM4_CCM_CONTEXT_STATE(p_context) &&
        sm4_ccm_enc != SM4_CCM_CONTEXT_STATE(p_context) &&
        sm4_ccm_dec != SM4_CCM_CONTEXT_STATE(p_context) &&
        sm4_ccm_get_tag != SM4_CCM_CONTEXT_STATE(p_context)) {

        status = MBX_SET_STS16_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
        return status;
    }

    /* Don't process buffers with input pointers equal to zero and set bad status for tags of invalid length */
    for (buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        if (pa_tag[buf_no] == NULL) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
            mb_mask &= ~(0x1 << buf_no);
        } else {
            if (tag_len[buf_no] < 4 || tag_len[buf_no] > 16 || tag_len[buf_no] & 0x1) {
                status = MBX_SET_STS16(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
                mb_mask &= ~(0x1 << buf_no);
            } else {
                /* Check if total processed length is not equal to total message length passed at init */
                if (processed_len[buf_no] != msg_len[buf_no]) {
                    status = MBX_SET_STS16(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
                    mb_mask &= ~(0x1 << buf_no);
                }
            }
        }
    }

#if (_MBX >= _MBX_K1)
    if (MBX_IS_ANY_OK_STS16(status)) {
        status |= sm4_ccm_get_tag_mb16(pa_tag, tag_len, (__mmask16)mb_mask, p_context);
    }
#else
    MBX_UNREFERENCED_PARAMETER(mb_mask);
    status = MBX_SET_STS16_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
