/*************************************************************************
* Copyright (C) 2002 Intel Corporation
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
#include <internal/common/ifma_cvt52.h>
#include <internal/ecnist/ifma_ecpoint_p521.h>
#include <internal/rsa/ifma_rsa_arith.h>

#ifndef BN_OPENSSL_DISABLE
/*
// Computes shared key
// pa_shared_key[]   array of pointers to the shared keys
// pa_skey[]   array of pointers to the own (ephemeral) private keys
// pa_pubx[]   array of pointers to the party's public keys X-coordinates
// pa_puby[]   array of pointers to the party's public keys Y-coordinates
// pa_pubz[]   array of pointers to the party's public keys Z-coordinates  (or NULL, if affine coordinate requested)
// pBuffer     pointer to the scratch buffer
//
// Note:
// input party's public key depends on is pa_pubz[] parameter and represented either
//    - in (X:Y:Z) projective Jacobian coordinates
//    or
//    - in (x:y) affine coordinate
*/
DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdh_ssl_mb8)(int8u* pa_shared_key[8],
                                             const BIGNUM* const pa_skey[8],
                                             const BIGNUM* const pa_pubx[8],
                                             const BIGNUM* const pa_puby[8],
                                             const BIGNUM* const pa_pubz[8],
                                             int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* pa_pubz!=0 means the output is in Jacobian projective coordinates */
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_shared_key || NULL == pa_skey || NULL == pa_pubx || NULL == pa_puby) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int8u* shared      = pa_shared_key[buf_no];
        const BIGNUM* skey = pa_skey[buf_no];
        const BIGNUM* pubx = pa_pubx[buf_no];
        const BIGNUM* puby = pa_puby[buf_no];
        const BIGNUM* pubz = use_jproj_coords ? pa_pubz[buf_no] : NULL;

        /* if any of pointer NULL set error status */
        if (NULL == shared || NULL == skey || NULL == pubx || NULL == puby ||
            (use_jproj_coords && NULL == pubz)) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdh_ssl_mb8(
        pa_shared_key, pa_skey, pa_pubx, pa_puby, pa_pubz, pBuffer, use_jproj_coords);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
#endif // BN_OPENSSL_DISABLE

DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdh_mb8)(int8u* pa_shared_key[8],
                                         const int64u* const pa_skey[8],
                                         const int64u* const pa_pubx[8],
                                         const int64u* const pa_puby[8],
                                         const int64u* const pa_pubz[8],
                                         int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* pa_pubz!=0 means the output is in Jacobian projective coordinates */
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_shared_key || NULL == pa_skey || NULL == pa_pubx || NULL == pa_puby) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int8u* shared      = pa_shared_key[buf_no];
        const int64u* skey = pa_skey[buf_no];
        const int64u* pubx = pa_pubx[buf_no];
        const int64u* puby = pa_puby[buf_no];
        const int64u* pubz = use_jproj_coords ? pa_pubz[buf_no] : NULL;

        /* if any of pointer NULL set error status */
        if (NULL == shared || NULL == skey || NULL == pubx || NULL == puby ||
            (use_jproj_coords && NULL == pubz)) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdh_mb8(
        pa_shared_key, pa_skey, pa_pubx, pa_puby, pa_pubz, pBuffer, use_jproj_coords);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
