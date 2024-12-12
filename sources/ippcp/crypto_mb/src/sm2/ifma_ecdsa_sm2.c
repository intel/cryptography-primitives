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
#include <crypto_mb/ec_sm2.h>

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_cvt52.h>
#include <internal/sm2/ifma_ecpoint_sm2.h>
#include <internal/sm3/sm3_mb8.h>
#include <internal/rsa/ifma_rsa_arith.h>

#ifndef BN_OPENSSL_DISABLE
#include <openssl/bn.h>
#include <openssl/ec.h>
#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/ecdsa.h>
#endif
#endif

/*
// Computes SM2 ECDSA signature
// pa_sign_r[]       array of pointers to the computed r-components of the signatures
// pa_sign_s[]       array of pointers to the computed s-components of the signatures
// pa_user_id[]      array of pointers to the users ID
// user_id_len[]     array of users ID length
// pa_msg[]          array of pointers to the messages are being signed
// msg_len[]         array of messages length
// pa_eph_skey[]     array of pointers to the signer's ephemeral private keys
// pa_reg_skey[]     array of pointers to the signer's regular private keys
// pa_pubx[]         array of pointers to the party's public keys X-coordinates
// pa_puby[]         array of pointers to the party's public keys Y-coordinates
// pa_pubz[]         array of pointers to the party's public keys Z-coordinates
// pBuffer           pointer to the scratch buffer
*/
DLL_PUBLIC
mbx_status OWNAPI(mbx_sm2_ecdsa_sign_mb8)(int8u* pa_sign_r[8],
                                          int8u* pa_sign_s[8],
                                          const int8u* const pa_user_id[8],
                                          const int user_id_len[8],
                                          const int8u* const pa_msg[8],
                                          const int msg_len[8],
                                          const int64u* const pa_eph_skey[8],
                                          const int64u* const pa_reg_skey[8],
                                          const int64u* const pa_pubx[8],
                                          const int64u* const pa_puby[8],
                                          const int64u* const pa_pubz[8],
                                          int8u* pBuffer)
{
    mbx_status status    = 0;
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_sign_r || NULL == pa_sign_s || NULL == pa_user_id || NULL == user_id_len ||
        NULL == pa_msg || NULL == msg_len || NULL == pa_eph_skey || NULL == pa_reg_skey ||
        NULL == pa_pubx || NULL == pa_puby) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    int user_id_len_checked[8];

    /* check pointers and values */
    for (int buf_no = 0; buf_no < 8; buf_no++) {
        const int8u* r        = pa_sign_r[buf_no];
        const int8u* s        = pa_sign_s[buf_no];
        const int8u* id       = pa_user_id[buf_no];
        const int8u* msg      = pa_msg[buf_no];
        const int64u* eph_key = pa_eph_skey[buf_no];
        const int64u* reg_key = pa_reg_skey[buf_no];
        const int64u* pubx    = pa_pubx[buf_no];
        const int64u* puby    = pa_puby[buf_no];
        const int64u* pubz    = use_jproj_coords ? pa_pubz[buf_no] : NULL;

        user_id_len_checked[buf_no] = user_id_len[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == r || NULL == s || NULL == id || NULL == msg || NULL == eph_key ||
            NULL == reg_key || NULL == pubx || NULL == puby || (use_jproj_coords && NULL == pubz)) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
        if (msg_len[buf_no] < 0) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
        }
        if ((user_id_len[buf_no] > 0xFFFF) || (user_id_len[buf_no] < 0)) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
            user_id_len_checked[buf_no] = 0;
        }
    }

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_sm2_ecdsa_sign_mb8(pa_sign_r,
                                                 pa_sign_s,
                                                 pa_user_id,
                                                 user_id_len,
                                                 pa_msg,
                                                 msg_len,
                                                 pa_eph_skey,
                                                 pa_reg_skey,
                                                 pa_pubx,
                                                 pa_puby,
                                                 pa_pubz,
                                                 pBuffer,
                                                 use_jproj_coords,
                                                 user_id_len_checked);
#else
    MBX_UNREFERENCED_PARAMETER(user_id_len_checked);
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

/*
// Verifies SM2 ECDSA signature
// pa_sign_r[]       array of pointers to the computed r-components of the signatures
// pa_sign_s[]       array of pointers to the computed s-components of the signatures
// pa_msg[]          array of pointers to the messages that have been signed
// pa_user_id[]      array of pointers to the users ID
// user_id_len[]     array of users ID length
// pa_msg[]          array of pointers to the messages are being signed
// msg_len[]         array of messages length
// pa_pubx[]         array of pointers to the signer's public keys X-coordinates
// pa_puby[]         array of pointers to the signer's public keys Y-coordinates
// pa_pubz[]         array of pointers to the signer's public keys Z-coordinates  (or NULL, if affine coordinate requested)
// pBuffer           pointer to the scratch buffer
*/
DLL_PUBLIC
mbx_status OWNAPI(mbx_sm2_ecdsa_verify_mb8)(const int8u* const pa_sign_r[8],
                                            const int8u* const pa_sign_s[8],
                                            const int8u* const pa_user_id[8],
                                            const int user_id_len[8],
                                            const int8u* const pa_msg[8],
                                            const int msg_len[8],
                                            const int64u* const pa_pubx[8],
                                            const int64u* const pa_puby[8],
                                            const int64u* const pa_pubz[8],
                                            int8u* pBuffer)
{
    mbx_status status    = 0;
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_sign_r || NULL == pa_sign_s || NULL == pa_user_id || NULL == user_id_len ||
        NULL == pa_msg || NULL == msg_len || NULL == pa_pubx || NULL == pa_puby) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    int user_id_len_checked[8];

    /* check pointers and values */
    for (int buf_no = 0; buf_no < 8; buf_no++) {
        const int8u* r     = pa_sign_r[buf_no];
        const int8u* s     = pa_sign_s[buf_no];
        const int8u* id    = pa_user_id[buf_no];
        const int8u* msg   = pa_msg[buf_no];
        const int64u* pubx = pa_pubx[buf_no];
        const int64u* puby = pa_puby[buf_no];
        const int64u* pubz = use_jproj_coords ? pa_pubz[buf_no] : NULL;

        user_id_len_checked[buf_no] = user_id_len[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == r || NULL == s || NULL == id || NULL == msg || NULL == pubx || NULL == puby ||
            (use_jproj_coords && NULL == pubz)) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
        if (msg_len[buf_no] < 0) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
        }
        if ((user_id_len[buf_no] > 0xFFFF) || (user_id_len[buf_no] < 0)) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
            user_id_len_checked[buf_no] = 0;
        }
    }

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_sm2_ecdsa_verify_mb8(pa_sign_r,
                                                   pa_sign_s,
                                                   pa_user_id,
                                                   user_id_len,
                                                   pa_msg,
                                                   msg_len,
                                                   pa_pubx,
                                                   pa_puby,
                                                   pa_pubz,
                                                   pBuffer,
                                                   use_jproj_coords,
                                                   user_id_len_checked);
#else
    MBX_UNREFERENCED_PARAMETER(user_id_len_checked);
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

/*
// OpenSSL's specific implementations
*/
#ifndef BN_OPENSSL_DISABLE

DLL_PUBLIC
mbx_status OWNAPI(mbx_sm2_ecdsa_sign_ssl_mb8)(int8u* pa_sign_r[8],
                                              int8u* pa_sign_s[8],
                                              const int8u* const pa_user_id[8],
                                              const int user_id_len[8],
                                              const int8u* const pa_msg[8],
                                              const int msg_len[8],
                                              const BIGNUM* const pa_eph_skey[8],
                                              const BIGNUM* const pa_reg_skey[8],
                                              const BIGNUM* const pa_pubx[8],
                                              const BIGNUM* const pa_puby[8],
                                              const BIGNUM* const pa_pubz[8],
                                              int8u* pBuffer)
{
    mbx_status status    = 0;
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_sign_r || NULL == pa_sign_s || NULL == pa_user_id || NULL == user_id_len ||
        NULL == pa_msg || NULL == msg_len || NULL == pa_eph_skey || NULL == pa_reg_skey ||
        NULL == pa_pubx || NULL == pa_puby) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    int user_id_len_checked[8];

    /* check pointers and values */
    for (int buf_no = 0; buf_no < 8; buf_no++) {
        const int8u* r        = pa_sign_r[buf_no];
        const int8u* s        = pa_sign_s[buf_no];
        const int8u* id       = pa_user_id[buf_no];
        const int8u* msg      = pa_msg[buf_no];
        const BIGNUM* eph_key = pa_eph_skey[buf_no];
        const BIGNUM* reg_key = pa_reg_skey[buf_no];
        const BIGNUM* pubx    = pa_pubx[buf_no];
        const BIGNUM* puby    = pa_puby[buf_no];
        const BIGNUM* pubz    = use_jproj_coords ? pa_pubz[buf_no] : NULL;

        user_id_len_checked[buf_no] = user_id_len[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == r || NULL == s || NULL == id || NULL == msg || NULL == eph_key ||
            NULL == reg_key || NULL == pubx || NULL == puby || (use_jproj_coords && NULL == pubz)) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
        if (msg_len[buf_no] < 0) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
        }
        if ((user_id_len[buf_no] > 0xFFFF) || (user_id_len[buf_no] < 0)) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
            user_id_len_checked[buf_no] = 0;
        }
    }

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_sm2_ecdsa_sign_ssl_mb8(pa_sign_r,
                                                     pa_sign_s,
                                                     pa_user_id,
                                                     user_id_len,
                                                     pa_msg,
                                                     msg_len,
                                                     pa_eph_skey,
                                                     pa_reg_skey,
                                                     pa_pubx,
                                                     pa_puby,
                                                     pa_pubz,
                                                     pBuffer,
                                                     use_jproj_coords,
                                                     user_id_len_checked);
#else
    MBX_UNREFERENCED_PARAMETER(user_id_len_checked);
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

DLL_PUBLIC
mbx_status OWNAPI(mbx_sm2_ecdsa_verify_ssl_mb8)(const ECDSA_SIG* const pa_sig[8],
                                                const int8u* const pa_user_id[8],
                                                const int user_id_len[8],
                                                const int8u* const pa_msg[8],
                                                const int msg_len[8],
                                                const BIGNUM* const pa_pubx[8],
                                                const BIGNUM* const pa_puby[8],
                                                const BIGNUM* const pa_pubz[8],
                                                int8u* pBuffer)
{
    mbx_status status    = 0;
    int use_jproj_coords = NULL != pa_pubz;

    /* test input pointers */
    if (NULL == pa_sig || NULL == pa_user_id || NULL == user_id_len || NULL == pa_msg ||
        NULL == msg_len || NULL == pa_pubx || NULL == pa_puby) {
        status = MBX_SET_STS_ALL(MBX_STATUS_NULL_PARAM_ERR);
        return status;
    }

    int user_id_len_checked[8];

    /* check pointers and values */
    for (int buf_no = 0; buf_no < 8; buf_no++) {
        const ECDSA_SIG* sig = pa_sig[buf_no];
        const int8u* id      = pa_user_id[buf_no];
        const int8u* msg     = pa_msg[buf_no];
        const BIGNUM* pubx   = pa_pubx[buf_no];
        const BIGNUM* puby   = pa_puby[buf_no];
        const BIGNUM* pubz   = use_jproj_coords ? pa_pubz[buf_no] : NULL;

        user_id_len_checked[buf_no] = user_id_len[buf_no];

        /* if any of pointer NULL set error status */
        if (NULL == sig || NULL == id || NULL == msg || NULL == pubx || NULL == puby ||
            (use_jproj_coords && NULL == pubz)) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_NULL_PARAM_ERR);
        }
        if (msg_len[buf_no] < 0) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
        }
        if ((user_id_len[buf_no] > 0xFFFF) || (user_id_len[buf_no] < 0)) {
            status |= MBX_SET_STS(status, buf_no, MBX_STATUS_MISMATCH_PARAM_ERR);
            user_id_len_checked[buf_no] = 0;
        }
    }

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

#if (_MBX >= _MBX_K1)
    status |= internal_avx512_sm2_ecdsa_verify_ssl_mb8(pa_sig,
                                                       pa_user_id,
                                                       user_id_len,
                                                       pa_msg,
                                                       msg_len,
                                                       pa_pubx,
                                                       pa_puby,
                                                       pa_pubz,
                                                       pBuffer,
                                                       use_jproj_coords,
                                                       user_id_len_checked);
#else
    MBX_UNREFERENCED_PARAMETER(user_id_len_checked);
    status = MBX_SET_STS_ALL(MBX_STATUS_UNSUPPORTED_ISA_ERR);
#endif /* #if (_MBX>=_MBX_K1) */
    return status;
}

#endif /* BN_OPENSSL_DISABLE */
