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

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_math.h>
#include <internal/common/ifma_cvt52.h>
#include <internal/rsa/ifma_rsa_arith.h>

#include <crypto_mb/ed25519.h>
#include <internal/ed25519/ifma_arith_ed25519.h>
#include <internal/ed25519/ifma_arith_p25519.h>
#include <internal/ed25519/ifma_arith_n25519.h>
#include <internal/ed25519/sha512.h>

/*
// Computes public key
// pa_public_key[]   array of pointers to the public keys X-coordinates
// pa_secret_key[]   array of pointers to the public keys Y-coordinates
*/
DLL_PUBLIC
mbx_status OWNAPI(mbx_ed25519_public_key_mb8)(ed25519_public_key* pa_public_key[8],
                                              const ed25519_private_key* const pa_private_key[8])
{
    mbx_status status = MBX_STATUS_OK;

    /* test input pointers */
    if (NULL == pa_private_key || NULL == pa_public_key) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    int buf_no;
    for (buf_no = 0; buf_no < 8; buf_no++) {
        const ed25519_private_key* private_key = pa_private_key[buf_no];
        ed25519_public_key* public_key         = pa_public_key[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == private_key || NULL == public_key) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_ed25519_public_key_mb8(pa_public_key, pa_private_key);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_ed25519_sign_mb8)(ed25519_sign_component* pa_sign_r[8],
                                        ed25519_sign_component* pa_sign_s[8],
                                        const int8u* const pa_msg[8],
                                        const int32u msgLen[8],
                                        const ed25519_private_key* const pa_private_key[8],
                                        const ed25519_public_key* const pa_public_key[8])
{
    mbx_status status = MBX_STATUS_OK;

    /* test input pointers */
    if (NULL == pa_sign_r || NULL == pa_sign_s || NULL == pa_msg || NULL == msgLen ||
        NULL == pa_private_key || NULL == pa_public_key) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    int buf_no;
    for (buf_no = 0; buf_no < 8; buf_no++) {
        ed25519_sign_component* sign_r    = pa_sign_r[buf_no];
        ed25519_sign_component* sign_s    = pa_sign_s[buf_no];
        const int8u* msg                  = pa_msg[buf_no];
        const ed25519_private_key* secret = pa_private_key[buf_no];
        const ed25519_public_key* public  = pa_public_key[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == sign_r || NULL == sign_s || NULL == msg || NULL == secret || NULL == public) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_ed25519_sign_mb8(
        pa_sign_r, pa_sign_s, pa_msg, msgLen, pa_private_key, pa_public_key);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_ed25519_verify_mb8)(const ed25519_sign_component* const pa_sign_r[8],
                                          const ed25519_sign_component* const pa_sign_s[8],
                                          const int8u* const pa_msg[8],
                                          const int32u msgLen[8],
                                          const ed25519_public_key* const pa_public_key[8])
{
    mbx_status status = MBX_STATUS_OK;

    /* test input pointers */
    if (NULL == pa_sign_r || NULL == pa_sign_s || NULL == pa_msg || NULL == msgLen ||
        NULL == pa_public_key) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    int buf_no;
    for (buf_no = 0; buf_no < 8; buf_no++) {
        const ed25519_sign_component* sign_r = pa_sign_r[buf_no];
        const ed25519_sign_component* sign_s = pa_sign_s[buf_no];
        const int8u* msg                     = pa_msg[buf_no];
        const ed25519_public_key* public     = pa_public_key[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == sign_r || NULL == sign_s || NULL == msg || NULL == public) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

#if (_MBX >= _MBX_K1)
    status |=
        internal_avx512_ed25519_verify_mb8(pa_sign_r, pa_sign_s, pa_msg, msgLen, pa_public_key);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
