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

#include <crypto_mb/ec_nistp256.h>

#ifndef BN_OPENSSL_DISABLE
#include <openssl/ecdsa.h>
#endif

/* Pairwise Consistency Test for EC p256 keypair */
/* KAT data taken from FIPS 186-4 examples */
// msg ==
// "5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf"
// "416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5"
// "473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17c"
// "c934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8"

/* msgDigest == SHA-256(msg) */
static const int8u msg_digest[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x44, 0xac, 0xf6, 0xb7, 0xe3, 0x6c, 0x13, 0x42, 0xc2, 0xc5, 0x89, 0x72, 0x04, 0xfe, 0x09, 0x50,
    0x4e, 0x1e, 0x2e, 0xfb, 0x1a, 0x90, 0x03, 0x77, 0xdb, 0xc4, 0xe7, 0xa6, 0xa1, 0x33, 0xec, 0x56
};
/* private key */
static const int8u d[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x64, 0xb4, 0x72, 0xda, 0x6d, 0xa5, 0x54, 0xca, 0xac, 0x3e, 0x4e, 0x0b, 0x13, 0xc8, 0x44, 0x5b,
    0x1a, 0x77, 0xf4, 0x59, 0xee, 0xa8, 0x4f, 0x1f, 0x58, 0x8b, 0x5f, 0x71, 0x3d, 0x42, 0x9b, 0x51
};
static const int8u k[MBX_NISTP256_DATA_BYTE_LEN] = {
    0xde, 0x68, 0x2a, 0x64, 0x87, 0x07, 0x67, 0xb9, 0x33, 0x5d, 0x4f, 0x82, 0x47, 0x62, 0x4a, 0x3b,
    0x7f, 0x3c, 0xe9, 0xf9, 0x45, 0xf2, 0x80, 0xa2, 0x61, 0x6a, 0x90, 0x4b, 0xb1, 0xbb, 0xa1, 0x94
};

/* output signature buffers */
static int8u out_r[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];
static int8u out_s[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp256_ecpublic_key_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;
    /* function input parameters */
    // private key pair
    const int64u* const pa_prv_d[MBX_LANES] = { (int64u*)d, (int64u*)d, (int64u*)d, (int64u*)d,
                                                (int64u*)d, (int64u*)d, (int64u*)d, (int64u*)d };
    const int64u* const pa_prv_k[MBX_LANES] = { (int64u*)k, (int64u*)k, (int64u*)k, (int64u*)k,
                                                (int64u*)k, (int64u*)k, (int64u*)k, (int64u*)k };
    // msg digest
    const int8u* const pa_pub_msg_digest[MBX_LANES] = { msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest };

    /* function output parameters */
    //  output public key
    int8u out_Qx[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];
    int8u out_Qy[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];
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
    sts         = mbx_nistp256_ecpublic_key_mb8(pa_pub_Qx, pa_pub_Qy, NULL, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);
    if (test_result != MBX_ALGO_SELFTEST_OK) {
        return test_result;
    }

    // Add const qualifiers to arrays
    const int64u* const* _pa_pub_Qx = (const int64u* const*)pa_pub_Qx;
    const int64u* const* _pa_pub_Qy = (const int64u* const*)pa_pub_Qy;

    // sign and verify with the generated keypair
    sts = mbx_nistp256_ecdsa_sign_mb8(
        pa_sign_r, pa_sign_s, pa_pub_msg_digest, pa_prv_k, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);
    if (test_result != MBX_ALGO_SELFTEST_OK) {
        return test_result;
    }

    // Add const qualifiers to arrays
    const int8u* const* _pa_sign_r = (const int8u* const*)pa_sign_r;
    const int8u* const* _pa_sign_s = (const int8u* const*)pa_sign_s;

    sts = mbx_nistp256_ecdsa_verify_mb8(
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
fips_test_status fips_selftest_mbx_nistp256_ecpublic_key_ssl_mb8(void)
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

    // set ssl private key
    BN_lebin2bn(d, MBX_NISTP256_DATA_BYTE_LEN, BN_d);
    BN_lebin2bn(k, MBX_NISTP256_DATA_BYTE_LEN, BN_k);
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
    sts         = mbx_nistp256_ecpublic_key_ssl_mb8(pa_pub_Qx, pa_pub_Qy, NULL, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);
    if (test_result != MBX_ALGO_SELFTEST_OK) {
        MEM_FREE(pa_pub_Qx, pa_pub_Qy, pa_sig, BN_d, BN_k)
        return test_result;
    }

    // Add const qualifiers to arrays
    const BIGNUM* const* _pa_pub_Qx = (const BIGNUM* const*)pa_pub_Qx;
    const BIGNUM* const* _pa_pub_Qy = (const BIGNUM* const*)pa_pub_Qy;

    // sign and verify with the generated keypair
    sts = mbx_nistp256_ecdsa_sign_ssl_mb8(
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

        BN_bin2bn(out_r[i], MBX_NISTP256_DATA_BYTE_LEN, BN_r);
        BN_bin2bn(out_s[i], MBX_NISTP256_DATA_BYTE_LEN, BN_s);
        ECDSA_SIG_set0(pa_sig[i], BN_r, BN_s);
    }
    sts = mbx_nistp256_ecdsa_verify_ssl_mb8(
        (const ECDSA_SIG* const*)pa_sig, pa_pub_msg_digest, _pa_pub_Qx, _pa_pub_Qy, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_KAT_ERR);

    MEM_FREE(pa_pub_Qx, pa_pub_Qy, pa_sig, BN_d, BN_k)
    return test_result;
}

#endif // BN_OPENSSL_DISABLE
#endif // MBX_FIPS_MODE
