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

#include <internal/sm4/sm4_mb.h>
#include <internal/common/ifma_defs.h>
#include <internal/rsa/ifma_rsa_arith.h>

DLL_PUBLIC
mbx_status16 OWNAPI(mbx_sm4_set_key_mb16)(mbx_sm4_key_schedule* key_sched,
                                          const sm4_key* pa_key[SM4_LINES])
{
    int buf_no;
    mbx_status16 status = 0;
    int16u mb_mask      = 0xFFFF;

    /* Test input pointers */
    if (NULL == key_sched || NULL == pa_key) {
        status = MBX_SET_STS16_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* Don't process buffers with input pointers equal to zero */
    for (buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        if (pa_key[buf_no] == NULL) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
            mb_mask &= ~(0x1 << buf_no);
        }
    }

#if (_MBX >= _MBX_K1)
    if (MBX_IS_ANY_OK_STS16(status))
        status |= internal_avx512_sm4_set_round_keys_mb16(
            (int32u**)key_sched, (const int8u**)pa_key, (__mmask16)mb_mask);
#else
    MBX_UNREFERENCED_PARAMETER(mb_mask);
    status = MBX_SET_STS16_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status16 OWNAPI(mbx_sm4_xts_set_keys_mb16)(mbx_sm4_key_schedule* key_sched1,
                                               mbx_sm4_key_schedule* key_sched2,
                                               const sm4_xts_key* pa_key[SM4_LINES])
{
    int buf_no;
    mbx_status16 status = 0;
    int16u mb_mask      = 0xFFFF;

    /* Test input pointers */
    if (NULL == key_sched1 || NULL == key_sched2 || NULL == pa_key)
        return MBX_SET_STS16_ALL(MBX_STATUS_NULL_PARAM_ERR);

    /* Don't process buffers with input pointers equal to zero */
    for (buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        if (pa_key[buf_no] == NULL) {
            status = MBX_SET_STS16(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
            mb_mask &= ~(0x1 << buf_no);
        }
    }

#if (_MBX >= _MBX_K1)
    if (MBX_IS_ANY_OK_STS16(status))
        status |= internal_avx512_sm4_xts_set_keys_mb16(
            key_sched1, key_sched2, pa_key, (__mmask16)mb_mask);
#else
    MBX_UNREFERENCED_PARAMETER(mb_mask);
    status = MBX_SET_STS16_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
