/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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

#include <crypto_mb/status.h>
#include <crypto_mb/sm4.h>

#include <internal/common/ifma_defs.h>
#include <internal/sm4/sm4_mb.h>

DLL_PUBLIC
mbx_status16 OWNAPI(mbx_sm4_decrypt_cfb128_mb16)(int8u* pa_out[SM4_LINES],
                                                 const int8u* pa_inp[SM4_LINES],
                                                 const int len[SM4_LINES],
                                                 const mbx_sm4_key_schedule* key_sched,
                                                 const int8u* pa_iv[SM4_LINES])
{
    int buf_no;
    mbx_status16 status = 0;
    int16u mb_mask      = 0xFFFF;

    /* Test input pointers */
    if (NULL == pa_out || NULL == pa_inp || NULL == len || NULL == key_sched || NULL == pa_iv) {
        status = MBX_SET_STS16_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* Test input data length, input pointers and stream integrity*/
    for (buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        if (pa_out[buf_no] == NULL || pa_inp[buf_no] == NULL || pa_iv[buf_no] == NULL) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
            /* Do not process empty buffers */
            mb_mask &= ~(0x1 << buf_no);
        }
        if ((len[buf_no] < 0) || (len[buf_no] & (SM4_BLOCK_SIZE - 1))) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
            /* Do not process non-valid buffers */
            mb_mask &= ~(0x1 << buf_no);
        }
    }

#if (_MBX >= _MBX_K1)
    if (MBX_IS_ANY_OK_STS16(status))
        status |= sm4_cfb128_dec_kernel_mb16(pa_out,
                                             (const int8u**)pa_inp,
                                             (const int*)len,
                                             (const int32u**)key_sched,
                                             pa_iv,
                                             (__mmask16)mb_mask);
#else
    MBX_UNREFERENCED_PARAMETER(mb_mask);
    status = MBX_SET_STS16_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
