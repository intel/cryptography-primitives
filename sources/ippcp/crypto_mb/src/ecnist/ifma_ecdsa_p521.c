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
#include <openssl/bn.h>
#include <openssl/ec.h>
#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/ecdsa.h>
#endif
#endif

/*
// ECDSA kernels
*/

/*
// pre-computation of ECDSA signature
//
// pa_inv_eph_skey[] array of pointers to the inversion of signer's ephemeral private keys
// pa_sign_rp[]      array of pointers to the r-components of the signatures
// pa_eph_skey[]     array of pointers to the ephemeral (nonce) signer's ephemeral private keys
// pBuffer           pointer to the scratch buffer
//
// function computes two values that does not depend on the message to be signed
// - inversion of signer's ephemeral (nonce) keys
// - r-component of the signature
// and are later used during the signing process
*/
DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdsa_sign_setup_mb8)(int64u* pa_inv_eph_skey[8],
                                                     int64u* pa_sign_rp[8],
                                                     const int64u* const pa_eph_skey[8],
                                                     int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* test input pointers */
    if (NULL == pa_inv_eph_skey || NULL == pa_sign_rp || NULL == pa_eph_skey) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check data pointers */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int64u* pinv_key   = pa_inv_eph_skey[buf_no];
        int64u* psign_rp   = pa_sign_rp[buf_no];
        const int64u* pkey = pa_eph_skey[buf_no];
        /* if any of pointer NULL set error status */
        if (NULL == pinv_key || NULL == psign_rp || NULL == pkey) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }
    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdsa_sign_setup_mb8(
        pa_inv_eph_skey, pa_sign_rp, pa_eph_skey, pBuffer);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

/*
// computes ECDSA signature
//
// pa_sign_r[]       array of pointers to the r-components of the signatures
// pa_sign_s[]       array of pointers to the s-components of the signatures
// pa_msg[]          array of pointers to the messages are being signed
// pa_sign_rp[]      array of pointers to the pre-computed r-components of the signatures
// pa_inv_eph_skey[] array of pointers to the inversion of signer's ephemeral private keys
// pa_reg_skey[]     array of pointers to the regular signer's ephemeral (nonce) private keys
// pBuffer           pointer to the scratch buffer
*/
DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdsa_sign_complete_mb8)(int8u* pa_sign_r[8],
                                                        int8u* pa_sign_s[8],
                                                        const int8u* const pa_msg[8],
                                                        const int64u* const pa_sign_rp[8],
                                                        const int64u* const pa_inv_eph_skey[8],
                                                        const int64u* const pa_reg_skey[8],
                                                        int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* test input pointers */
    if (NULL == pa_sign_r || NULL == pa_sign_s || NULL == pa_msg || NULL == pa_sign_rp ||
        NULL == pa_inv_eph_skey || NULL == pa_reg_skey) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check data pointers */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int8u* psign_r             = pa_sign_r[buf_no];
        int8u* psign_s             = pa_sign_s[buf_no];
        const int8u* pmsg          = pa_msg[buf_no];
        const int64u* psign_pr     = pa_sign_rp[buf_no];
        const int64u* pinv_eph_key = pa_inv_eph_skey[buf_no];
        const int64u* preg_key     = pa_reg_skey[buf_no];
        /* if any of pointer NULL set error status */
        if (NULL == psign_r || NULL == psign_s || NULL == pmsg || NULL == psign_pr ||
            NULL == pinv_eph_key || NULL == preg_key) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdsa_sign_complete_mb8(
        pa_sign_r, pa_sign_s, pa_msg, pa_sign_rp, pa_inv_eph_skey, pa_reg_skey, pBuffer);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

/*
// Computes ECDSA signature
// pa_sign_r[]       array of pointers to the computed r-components of the signatures
// pa_sign_s[]       array of pointers to the computed s-components of the signatures
// pa_msg[]          array of pointers to the messages are being signed
// pa_eph_skey[]     array of pointers to the signer's ephemeral (nonce) private keys
// pa_reg_skey[]     array of pointers to the signer's regular (long term) private keys
// pBuffer           pointer to the scratch buffer
*/
DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdsa_sign_mb8)(int8u* pa_sign_r[8],
                                               int8u* pa_sign_s[8],
                                               const int8u* const pa_msg[8],
                                               const int64u* const pa_eph_skey[8],
                                               const int64u* const pa_reg_skey[8],
                                               int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* test input pointers */
    if (NULL == pa_sign_r || NULL == pa_sign_s || NULL == pa_msg || NULL == pa_eph_skey ||
        NULL == pa_reg_skey) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }
    /* check data pointers */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int8u* psign_r         = pa_sign_r[buf_no];
        int8u* psign_s         = pa_sign_s[buf_no];
        const int8u* pmsg      = pa_msg[buf_no];
        const int64u* peph_key = pa_eph_skey[buf_no];
        const int64u* preg_key = pa_reg_skey[buf_no];
        /* if any of pointer NULL set error status */
        if (NULL == psign_r || NULL == psign_s || NULL == pmsg || NULL == peph_key ||
            NULL == preg_key) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }
    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdsa_sign_mb8(
        pa_sign_r, pa_sign_s, pa_msg, pa_eph_skey, pa_reg_skey, pBuffer);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

/*
// Verifies ECDSA signature
// pa_sign_r[]       array of pointers to the computed r-components of the signatures
// pa_sign_s[]       array of pointers to the computed s-components of the signatures
// pa_msg[]          array of pointers to the messages are being signed
// pa_pubx[]         array of pointers to the public keys X-coordinates
// pa_puby[]         array of pointers to the public keys Y-coordinates
// pa_pubz[]         array of pointers to the public keys Z-coordinates
// pBuffer           pointer to the scratch buffer
*/
DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdsa_verify_mb8)(const int8u* const pa_sign_r[8],
                                                 const int8u* const pa_sign_s[8],
                                                 const int8u* const pa_msg[8],
                                                 const int64u* const pa_pubx[8],
                                                 const int64u* const pa_puby[8],
                                                 const int64u* const pa_pubz[8],
                                                 int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_pubx || NULL == pa_puby || NULL == pa_msg || NULL == pa_sign_r ||
        NULL == pa_sign_s) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        const int64u* pubx = pa_pubx[buf_no];
        const int64u* puby = pa_puby[buf_no];
        const int64u* pubz = use_jproj_coords ? pa_pubz[buf_no] : NULL;
        const int8u* msg   = pa_msg[buf_no];
        const int8u* r     = pa_sign_r[buf_no];
        const int8u* s     = pa_sign_s[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == pubx || NULL == puby || NULL == msg || NULL == r || NULL == s ||
            (use_jproj_coords && NULL == pubz)) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

    /* if all pointers NULL exit */
    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdsa_verify_mb8(
        pa_sign_r, pa_sign_s, pa_msg, pa_pubx, pa_puby, pa_pubz, pBuffer, use_jproj_coords);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

/*
// OpenSSL's specific implementations
*/
#ifndef BN_OPENSSL_DISABLE

DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdsa_sign_setup_ssl_mb8)(BIGNUM* pa_inv_skey[8],
                                                         BIGNUM* pa_sign_rp[8],
                                                         const BIGNUM* const pa_eph_skey[8],
                                                         int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* test input pointers */
    if (NULL == pa_inv_skey || NULL == pa_sign_rp || NULL == pa_eph_skey) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check data pointers */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        const BIGNUM* pinv_key = pa_inv_skey[buf_no];
        const BIGNUM* psign_rp = pa_sign_rp[buf_no];
        const BIGNUM* pkey     = pa_eph_skey[buf_no];
        /* if any of pointer NULL set error status */
        if (NULL == pinv_key || NULL == psign_rp || NULL == pkey) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }
    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdsa_sign_setup_ssl_mb8(
        pa_inv_skey, pa_sign_rp, pa_eph_skey, pBuffer);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdsa_sign_complete_ssl_mb8)(int8u* pa_sign_r[8],
                                                            int8u* pa_sign_s[8],
                                                            const int8u* const pa_msg[8],
                                                            const BIGNUM* const pa_sign_rp[8],
                                                            const BIGNUM* const pa_inv_eph_skey[8],
                                                            const BIGNUM* const pa_reg_skey[8],
                                                            int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* test input pointers */
    if (NULL == pa_sign_r || NULL == pa_sign_s || NULL == pa_msg || NULL == pa_sign_rp ||
        NULL == pa_inv_eph_skey || NULL == pa_reg_skey) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check data pointers */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int8u* psign_r             = pa_sign_r[buf_no];
        int8u* psign_s             = pa_sign_s[buf_no];
        const int8u* pmsg          = pa_msg[buf_no];
        const BIGNUM* psign_pr     = pa_sign_rp[buf_no];
        const BIGNUM* pinv_eph_key = pa_inv_eph_skey[buf_no];
        const BIGNUM* preg_key     = pa_reg_skey[buf_no];
        if (NULL == psign_r || NULL == psign_s || NULL == pmsg || NULL == psign_pr ||
            NULL == pinv_eph_key || NULL == preg_key) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }
    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdsa_sign_complete_ssl_mb8(
        pa_sign_r, pa_sign_s, pa_msg, pa_sign_rp, pa_inv_eph_skey, pa_reg_skey, pBuffer);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdsa_sign_ssl_mb8)(int8u* pa_sign_r[8],
                                                   int8u* pa_sign_s[8],
                                                   const int8u* const pa_msg[8],
                                                   const BIGNUM* const pa_eph_skey[8],
                                                   const BIGNUM* const pa_reg_skey[8],
                                                   int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;

    /* test input pointers */
    if (NULL == pa_sign_r || NULL == pa_sign_s || NULL == pa_msg || NULL == pa_eph_skey ||
        NULL == pa_reg_skey) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }
    /* check data pointers */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        int8u* psign_r         = pa_sign_r[buf_no];
        int8u* psign_s         = pa_sign_s[buf_no];
        const int8u* pmsg      = pa_msg[buf_no];
        const BIGNUM* peph_key = pa_eph_skey[buf_no];
        const BIGNUM* preg_key = pa_reg_skey[buf_no];
        /* if any of pointer NULL set error status */
        if (NULL == psign_r || NULL == psign_s || NULL == pmsg || NULL == peph_key ||
            NULL == preg_key) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }
    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdsa_sign_ssl_mb8(
        pa_sign_r, pa_sign_s, pa_msg, pa_eph_skey, pa_reg_skey, pBuffer);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_nistp521_ecdsa_verify_ssl_mb8)(const ECDSA_SIG* const pa_sig[8],
                                                     const int8u* const pa_msg[8],
                                                     const BIGNUM* const pa_pubx[8],
                                                     const BIGNUM* const pa_puby[8],
                                                     const BIGNUM* const pa_pubz[8],
                                                     int8u* pBuffer)
{
    mbx_status status = 0;
    int buf_no;
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_pubx || NULL == pa_puby || NULL == pa_msg || NULL == pa_sig) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    /* check pointers and values */
    for (buf_no = 0; buf_no < 8; buf_no++) {
        const BIGNUM* pubx   = pa_pubx[buf_no];
        const BIGNUM* puby   = pa_puby[buf_no];
        const BIGNUM* pubz   = use_jproj_coords ? pa_pubz[buf_no] : NULL;
        const int8u* msg     = pa_msg[buf_no];
        const ECDSA_SIG* sig = pa_sig[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == pubx || NULL == puby || NULL == msg || NULL == sig ||
            (use_jproj_coords && NULL == pubz)) {
            status = MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
    }

    /* if all pointers NULL exit */
    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_nistp521_ecdsa_verify_ssl_mb8(
        pa_sig, pa_msg, pa_pubx, pa_puby, pa_pubz, pBuffer, use_jproj_coords);
#else
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

#endif // BN_OPENSSL_DISABLE
