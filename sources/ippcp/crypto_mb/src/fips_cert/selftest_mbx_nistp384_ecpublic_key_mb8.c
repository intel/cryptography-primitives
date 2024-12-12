/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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
#ifdef MBX_FIPS_MODE

#include <crypto_mb/fips_cert.h>
#include <internal/fips_cert/common.h>

#include <crypto_mb/ec_nistp384.h>

#ifndef BN_OPENSSL_DISABLE
#include <openssl/ecdsa.h>
#endif

/* Pairwise Consistency Test for EC p384 keypair */
/* KAT data taken from FIPS 186-4 examples */
// msg ==
// "9dd789ea25c04745d57a381f22de01fb0abd3c72dbdefd44e43213c189583eef"
// "85ba662044da3de2dd8670e6325154480155bbeebb702c75781ac32e13941860"
// "cb576fe37a05b757da5b5b418f6dd7c30b042e40f4395a342ae4dce05634c336"
// "25e2bc524345481f7e253d9551266823771b251705b4a85166022a37ac28f1bd"

/* msgDigest == SHA-384(msg) */
static const int8u msg_digest[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x96, 0x5b, 0x83, 0xf5, 0xd3, 0x4f, 0x74, 0x43, 0xeb, 0x88, 0xe7, 0x8f, 0xcc, 0x23, 0x47, 0x91,
    0x56, 0xc9, 0xcb, 0x00, 0x80, 0xdd, 0x68, 0x33, 0x4d, 0xac, 0x0a, 0xd3, 0x3b, 0xa8, 0xc7, 0x74,
    0x10, 0x0e, 0x44, 0x00, 0x63, 0xdb, 0x28, 0xb4, 0x0b, 0x51, 0xac, 0x37, 0x70, 0x5d, 0x4d, 0x70
};
/* private key pair */
static const int8u d[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x97, 0xac, 0x80, 0xb0, 0x4f, 0x9f, 0x44, 0x29, 0xbc, 0xe3, 0xbc, 0xcc, 0xb7, 0x5d, 0x2f, 0x95,
    0xc2, 0x5e, 0xf4, 0xbd, 0x6c, 0x1e, 0xa4, 0x0d, 0x37, 0x2e, 0xd5, 0x82, 0x44, 0x28, 0xa8, 0x46,
    0x3f, 0x4b, 0x3e, 0xdb, 0x61, 0x62, 0x2d, 0x18, 0x24, 0x43, 0xf1, 0x8d, 0x2d, 0x43, 0x1b, 0x20
};
static const int8u k[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x71, 0xc7, 0xc9, 0x25, 0x1f, 0x1e, 0xc8, 0x17, 0xf9, 0x97, 0xbf, 0xe5, 0x6c, 0xe1, 0x85, 0x88,
    0xdb, 0x83, 0x52, 0xa2, 0x58, 0x0f, 0xa0, 0x76, 0x66, 0x8c, 0xe2, 0x5c, 0x6e, 0xed, 0x9d, 0xdf,
    0x34, 0xfa, 0x46, 0x66, 0xe1, 0xc6, 0x33, 0xf7, 0x90, 0xe0, 0x78, 0x59, 0xf8, 0xab, 0xed, 0xdc
};
/* output signature buffers */
static int8u out_r[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];
static int8u out_s[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp384_ecpublic_key_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* function input parameters */
    // private key
    const int64u* const pa_prv_d[MBX_LANES] = { (int64u*)d, (int64u*)d, (int64u*)d, (int64u*)d,
                                                (int64u*)d, (int64u*)d, (int64u*)d, (int64u*)d };
    const int64u* const pa_prv_k[MBX_LANES] = { (int64u*)k, (int64u*)k, (int64u*)k, (int64u*)k,
                                                (int64u*)k, (int64u*)k, (int64u*)k, (int64u*)k };
    // msg digest
    const int8u* const pa_pub_msg_digest[MBX_LANES] = { msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest };

    /* function output parameters */
    /* output public key */
    int8u out_Qx[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];
    int8u out_Qy[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];
    // public key
    int64u* pa_pub_Qx[MBX_LANES] = { (int64u*)out_Qx[0], (int64u*)out_Qx[1], (int64u*)out_Qx[2],
                                     (int64u*)out_Qx[3], (int64u*)out_Qx[4], (int64u*)out_Qx[5],
                                     (int64u*)out_Qx[6], (int64u*)out_Qx[7] };
    int64u* pa_pub_Qy[MBX_LANES] = { (int64u*)out_Qy[0], (int64u*)out_Qy[1], (int64u*)out_Qy[2],
                                     (int64u*)out_Qy[3], (int64u*)out_Qy[4], (int64u*)out_Qy[5],
                                     (int64u*)out_Qy[6], (int64u*)out_Qy[7] };
    // output signature
    int8u* pa_sign_r[MBX_LANES] = { out_r[0], out_r[1], out_r[2], out_r[3],
                                    out_r[4], out_r[5], out_r[6], out_r[7] };
    int8u* pa_sign_s[MBX_LANES] = { out_s[0], out_s[1], out_s[2], out_s[3],
                                    out_s[4], out_s[5], out_s[6], out_s[7] };

    /* test function */
    mbx_status sts;
    sts         = mbx_nistp384_ecpublic_key_mb8(pa_pub_Qx, pa_pub_Qy, NULL, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);
    if (test_result != MBX_ALGO_SELFTEST_OK) {
        return test_result;
    }

    // Add const qualifiers to arrays
    const int64u* const* _pa_pub_Qx = (const int64u* const*)pa_pub_Qx;
    const int64u* const* _pa_pub_Qy = (const int64u* const*)pa_pub_Qy;

    // sign and verify with the generated keypair
    sts = mbx_nistp384_ecdsa_sign_mb8(
        pa_sign_r, pa_sign_s, pa_pub_msg_digest, pa_prv_k, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);
    if (test_result != MBX_ALGO_SELFTEST_OK) {
        return test_result;
    }

    // Add const qualifiers to arrays
    const int8u* const* _pa_sign_r = (const int8u* const*)pa_sign_r;
    const int8u* const* _pa_sign_s = (const int8u* const*)pa_sign_s;

    sts = mbx_nistp384_ecdsa_verify_mb8(
        _pa_sign_r, _pa_sign_s, pa_pub_msg_digest, _pa_pub_Qx, _pa_pub_Qy, NULL, NULL);
    // check the result of verification
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_KAT_ERR);

    return test_result;
}

#ifndef BN_OPENSSL_DISABLE

// memory free macro
#define MEM_FREE(BN_PTR_ARR1, BN_PTR_ARR2, SIG_PTR_ARR3, BN_PTR4, BN_PTR5) \
    {                                                                      \
        for (int i = 0; i < MBX_LANES; ++i) {                              \
            BN_free(BN_PTR_ARR1[i]);                                       \
            BN_free(BN_PTR_ARR2[i]);                                       \
            ECDSA_SIG_free(SIG_PTR_ARR3[i]);                               \
        }                                                                  \
        BN_free(BN_PTR4);                                                  \
        BN_free(BN_PTR5);                                                  \
    }

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp384_ecpublic_key_ssl_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* functions input parameters */
    // ssl private key
    BIGNUM* BN_d = BN_new();
    BIGNUM* BN_k = BN_new();
    // public key
    BIGNUM* pa_pub_Qx[MBX_LANES] = { BN_new(), BN_new(), BN_new(), BN_new(),
                                     BN_new(), BN_new(), BN_new(), BN_new() };
    BIGNUM* pa_pub_Qy[MBX_LANES] = { BN_new(), BN_new(), BN_new(), BN_new(),
                                     BN_new(), BN_new(), BN_new(), BN_new() };
    // signature for verify API
    ECDSA_SIG* const pa_sig[MBX_LANES] = { ECDSA_SIG_new(), ECDSA_SIG_new(), ECDSA_SIG_new(),
                                           ECDSA_SIG_new(), ECDSA_SIG_new(), ECDSA_SIG_new(),
                                           ECDSA_SIG_new(), ECDSA_SIG_new() };
    /* check if allocated memory is valid */
    if (NULL == BN_d || NULL == BN_k) {
        test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        if (NULL == pa_pub_Qx[i] || NULL == pa_pub_Qy[i] || NULL == pa_sig[i]) {
            test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
    }
    if (MBX_ALGO_SELFTEST_OK != test_result) {
        MEM_FREE(pa_pub_Qx, pa_pub_Qy, pa_sig, BN_d, BN_k)
        return test_result;
    }

    BN_lebin2bn(d, MBX_NISTP384_DATA_BYTE_LEN, BN_d);
    BN_lebin2bn(k, MBX_NISTP384_DATA_BYTE_LEN, BN_k);
    // private key
    const BIGNUM* const pa_prv_d[MBX_LANES] = {
        (const BIGNUM* const)BN_d, (const BIGNUM* const)BN_d, (const BIGNUM* const)BN_d,
        (const BIGNUM* const)BN_d, (const BIGNUM* const)BN_d, (const BIGNUM* const)BN_d,
        (const BIGNUM* const)BN_d, (const BIGNUM* const)BN_d
    };
    const BIGNUM* const pa_prv_k[MBX_LANES] = {
        (const BIGNUM* const)BN_k, (const BIGNUM* const)BN_k, (const BIGNUM* const)BN_k,
        (const BIGNUM* const)BN_k, (const BIGNUM* const)BN_k, (const BIGNUM* const)BN_k,
        (const BIGNUM* const)BN_k, (const BIGNUM* const)BN_k
    };
    // msg digest
    const int8u* const pa_pub_msg_digest[MBX_LANES] = { msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest };

    /* functions output parameters */
    // output signature for sign API
    int8u* pa_sign_r[MBX_LANES] = { out_r[0], out_r[1], out_r[2], out_r[3],
                                    out_r[4], out_r[5], out_r[6], out_r[7] };
    int8u* pa_sign_s[MBX_LANES] = { out_s[0], out_s[1], out_s[2], out_s[3],
                                    out_s[4], out_s[5], out_s[6], out_s[7] };

    /* test function */
    mbx_status sts;
    sts         = mbx_nistp384_ecpublic_key_ssl_mb8(pa_pub_Qx, pa_pub_Qy, NULL, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);
    if (test_result != MBX_ALGO_SELFTEST_OK) {
        MEM_FREE(pa_pub_Qx, pa_pub_Qy, pa_sig, BN_d, BN_k)
        return test_result;
    }

    // Add const qualifiers to arrays
    const BIGNUM* const* _pa_pub_Qx = (const BIGNUM* const*)pa_pub_Qx;
    const BIGNUM* const* _pa_pub_Qy = (const BIGNUM* const*)pa_pub_Qy;

    // sign and verify with the generated keypair
    sts = mbx_nistp384_ecdsa_sign_ssl_mb8(
        pa_sign_r, pa_sign_s, pa_pub_msg_digest, pa_prv_k, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);
    if (test_result != MBX_ALGO_SELFTEST_OK) {
        MEM_FREE(pa_pub_Qx, pa_pub_Qy, pa_sig, BN_d, BN_k)
        return test_result;
    }

    // fill ECDSA_SIG structure with the generated signature for verification
    for (int i = 0; i < MBX_LANES; ++i) {
        BIGNUM* BN_r = BN_new();
        BIGNUM* BN_s = BN_new();
        /* check if allocated memory is valid */
        if (NULL == BN_r || NULL == BN_s) {
            test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
            MEM_FREE(pa_pub_Qx, pa_pub_Qy, pa_sig, BN_d, BN_k)
            // Handled separately, since memory management of
            // these variables is transferred to sig below
            BN_free(BN_r);
            BN_free(BN_s);
            return test_result;
        }

        BN_bin2bn(out_r[i], MBX_NISTP384_DATA_BYTE_LEN, BN_r);
        BN_bin2bn(out_s[i], MBX_NISTP384_DATA_BYTE_LEN, BN_s);
        ECDSA_SIG_set0(pa_sig[i], BN_r, BN_s);
    }

    sts = mbx_nistp384_ecdsa_verify_ssl_mb8(
        (const ECDSA_SIG* const*)pa_sig, pa_pub_msg_digest, _pa_pub_Qx, _pa_pub_Qy, NULL, NULL);
    // check the result of verification
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_KAT_ERR);

    MEM_FREE(pa_pub_Qx, pa_pub_Qy, pa_sig, BN_d, BN_k)

    return test_result;
}

#endif // BN_OPENSSL_DISABLE
#endif // MBX_FIPS_MODE
