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
#include <internal/common/ifma_cvt52.h>
#include <internal/sm2/ifma_ecpoint_sm2.h>
#include <internal/rsa/ifma_rsa_arith.h>

#ifndef BN_OPENSSL_DISABLE
#include <openssl/bn.h>
#endif

#ifndef BN_OPENSSL_DISABLE
/*
// Computes public key
// pa_pubx[]   array of pointers to the public keys X-coordinates
// pa_puby[]   array of pointers to the public keys Y-coordinates
// pa_pubz[]   array of pointers to the public keys Z-coordinates (or NULL, if affine coordinate requested)
// pa_skey[]   array of pointers to the private keys
// pBuffer     pointer to the scratch buffer
//
// Note:
// output public key depends on pa_pubz[] parameter and represented either
//    - in (X:Y:Z) projective Jacobian coordinates if pa_pubz[] != NULL
//    or
//    - in (x:y) affine coordinate if pa_pubz[] == NULL
*/
DLL_PUBLIC
mbx_status OWNAPI(mbx_sm2_ecpublic_key_ssl_mb8)(BIGNUM* pa_pubx[8],
                                                BIGNUM* pa_puby[8],
                                                BIGNUM* pa_pubz[8],
                                                const BIGNUM* const pa_skey[8],
                                                int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* pa_bubz!=0 means the output is in Jacobian projective coordinates */
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_pubx || NULL == pa_puby || NULL == pa_skey) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        BIGNUM* out_x     = pa_pubx[buf_no];
        BIGNUM* out_y     = pa_puby[buf_no];
        BIGNUM* out_z     = use_jproj_coords ? pa_pubz[buf_no] : NULL;
        const BIGNUM* key = pa_skey[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == out_x || NULL == out_y || (use_jproj_coords && NULL == out_z) || NULL == key) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_sm2_ecpublic_key_ssl_mb8(
        pa_pubx, pa_puby, pa_pubz, pa_skey, pBuffer, use_jproj_coords);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
#endif // BN_OPENSSL_DISABLE

DLL_PUBLIC
mbx_status OWNAPI(mbx_sm2_ecpublic_key_mb8)(int64u* pa_pubx[8],
                                            int64u* pa_puby[8],
                                            int64u* pa_pubz[8],
                                            const int64u* const pa_skey[8],
                                            int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* pa_bubz!=0 means the output is in Jacobian projective coordinates */
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_pubx || NULL == pa_puby || NULL == pa_skey) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int64u* out_x     = pa_pubx[buf_no];
        int64u* out_y     = pa_puby[buf_no];
        int64u* out_z     = use_jproj_coords ? pa_pubz[buf_no] : NULL;
        const int64u* key = pa_skey[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == out_x || NULL == out_y || (use_jproj_coords && NULL == out_z) || NULL == key) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_sm2_ecpublic_key_mb8(
        pa_pubx, pa_puby, pa_pubz, pa_skey, pBuffer, use_jproj_coords);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}
