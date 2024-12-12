/*************************************************************************
* Copyright (C) 2019 Intel Corporation
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

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_math.h>
#include <internal/common/ifma_cvt52.h>
#include <internal/rsa/ifma_rsa_arith.h>

DLL_PUBLIC
mbx_status OWNAPI(mbx_x25519_mb8)(int8u* const pa_shared_key[8],
                                  const int8u* const pa_private_key[8],
                                  const int8u* const pa_public_key[8])
{
    mbx_status status = 0;
    int buf_no;

    /* test input pointers */
    if (NULL == pa_shared_key || NULL == pa_private_key || NULL == pa_public_key) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int64u* shared             = (int64u*)pa_shared_key[buf_no];
        const int64u* own_private  = (const int64u*)pa_private_key[buf_no];
        const int64u* party_public = (const int64u*)pa_public_key[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == shared || NULL == own_private || NULL == party_public) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
            continue;
        }
    }

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_x25519_mb8(pa_shared_key, pa_private_key, pa_public_key);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_x25519_public_key_mb8)(int8u* const pa_public_key[8],
                                             const int8u* const pa_private_key[8])
{
    mbx_status status = 0;

    /* test input pointers */
    if (NULL == pa_private_key || NULL == pa_public_key) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    int buf_no;
    for (buf_no = 0; buf_no < 8; buf_no++) {
        const int64u* own_private  = (const int64u*)pa_private_key[buf_no];
        const int64u* party_public = (const int64u*)pa_public_key[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == own_private || NULL == party_public) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
            continue;
        }
    }

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_x25519_public_key_mb8(pa_public_key, pa_private_key);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
