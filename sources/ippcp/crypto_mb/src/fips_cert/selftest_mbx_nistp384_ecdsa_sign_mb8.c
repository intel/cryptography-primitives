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

/* KAT TEST (taken from FIPS 186-4 examples) */
// msg ==
// "6b45d88037392e1371d9fd1cd174e9c1838d11c3d6133dc17e65fa0c485dcca9"
// "f52d41b60161246039e42ec784d49400bffdb51459f5de654091301a09378f93"
// "464d52118b48d44b30d781eb1dbed09da11fb4c818dbd442d161aba4b9edc79f"
// "05e4b7e401651395b53bd8b5bd3f2aaa6a00877fa9b45cadb8e648550b4c6cbe"

/* msgDigest == SHA-384(msg) */
static const int8u msg_digest[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x31, 0xa4, 0x52, 0xd6, 0x16, 0x4d, 0x90, 0x4b, 0xb5, 0x72, 0x4c, 0x87, 0x82, 0x80, 0x23, 0x1e,
    0xae, 0x70, 0x5c, 0x29, 0xce, 0x9d, 0x4b, 0xc7, 0xd5, 0x8e, 0x02, 0x0e, 0x10, 0x85, 0xf1, 0x7e,
    0xeb, 0xcc, 0x1a, 0x38, 0xf0, 0xed, 0x0b, 0xf2, 0xb3, 0x44, 0xd8, 0x1f, 0xbd, 0x89, 0x68, 0x25
};
/* key pair */
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
/* signature */
static const int8u r[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x50, 0x83, 0x5a, 0x92, 0x51, 0xba, 0xd0, 0x08, 0x10, 0x61, 0x77, 0xef, 0x00, 0x4b, 0x09, 0x1a,
    0x1e, 0x42, 0x35, 0xcd, 0x0d, 0xa8, 0x4f, 0xff, 0x54, 0x54, 0x2b, 0x0e, 0xd7, 0x55, 0xc1, 0xd6,
    0xf2, 0x51, 0x60, 0x9d, 0x14, 0xec, 0xf1, 0x8f, 0x9e, 0x1d, 0xdf, 0xe6, 0x9b, 0x94, 0x6e, 0x32
};

static const int8u s[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x04, 0x75, 0xf3, 0xd3, 0x0c, 0x64, 0x63, 0xb6, 0x46, 0xe8, 0xd3, 0xbf, 0x24, 0x55, 0x83, 0x03,
    0x14, 0x61, 0x1c, 0xbd, 0xe4, 0x04, 0xbe, 0x51, 0x8b, 0x14, 0x46, 0x4f, 0xdb, 0x19, 0x5f, 0xdc,
    0xc9, 0x2e, 0xb2, 0x22, 0xe6, 0x1f, 0x42, 0x6a, 0x4a, 0x59, 0x2c, 0x00, 0xa6, 0xa8, 0x97, 0x21
};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp384_ecdsa_sign_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* output signature */
    int8u out_r[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];
    int8u out_s[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];

    /* function input parameters */
    // msg digest
    const int8u* const pa_pub_msg_digest[MBX_LANES] = { msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest };
    // key pair
    const int64u* const pa_prv_d[MBX_LANES] = { (int64u*)d, (int64u*)d, (int64u*)d, (int64u*)d,
                                                (int64u*)d, (int64u*)d, (int64u*)d, (int64u*)d };
    const int64u* const pa_prv_k[MBX_LANES] = { (int64u*)k, (int64u*)k, (int64u*)k, (int64u*)k,
                                                (int64u*)k, (int64u*)k, (int64u*)k, (int64u*)k };

    // output signature
    int8u* pa_sign_r[MBX_LANES] = { out_r[0], out_r[1], out_r[2], out_r[3],
                                    out_r[4], out_r[5], out_r[6], out_r[7] };
    int8u* pa_sign_s[MBX_LANES] = { out_s[0], out_s[1], out_s[2], out_s[3],
                                    out_s[4], out_s[5], out_s[6], out_s[7] };

    /* test function */
    mbx_status sts;
    sts = mbx_nistp384_ecdsa_sign_mb8(
        pa_sign_r, pa_sign_s, pa_pub_msg_digest, pa_prv_k, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output signature to known answer
    int r_output_status;
    int s_output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        r_output_status =
            mbx_is_mem_eq(pa_sign_r[i], MBX_NISTP384_DATA_BYTE_LEN, r, MBX_NISTP384_DATA_BYTE_LEN);
        s_output_status =
            mbx_is_mem_eq(pa_sign_s[i], MBX_NISTP384_DATA_BYTE_LEN, s, MBX_NISTP384_DATA_BYTE_LEN);
        if (!r_output_status || !s_output_status) { // wrong output
            test_result = MBX_ALGO_SELFTEST_KAT_ERR;
        }
    }

    return test_result;
}

#ifndef BN_OPENSSL_DISABLE

#define MEM_FREE(BN_PTR1, BN_PTR2) \
    {                              \
        BN_free(BN_PTR1);          \
        BN_free(BN_PTR2);          \
    }

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp384_ecdsa_sign_ssl_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* ssl key pair */
    BIGNUM* BN_d = BN_new();
    BIGNUM* BN_k = BN_new();
    /* check if allocated memory is valid */
    if (NULL == BN_d || NULL == BN_k) {
        test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
        MEM_FREE(BN_d, BN_k)
        return test_result;
    }

    /* output signature */
    int8u out_r[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];
    int8u out_s[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];

    /* set ssl key pair */
    BN_lebin2bn(d, MBX_NISTP384_DATA_BYTE_LEN, BN_d);
    BN_lebin2bn(k, MBX_NISTP384_DATA_BYTE_LEN, BN_k);

    /* function input parameters */
    // msg digest
    const int8u* const pa_pub_msg_digest[MBX_LANES] = { msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest };
    // key pair
    const BIGNUM* pa_prv_d[MBX_LANES] = { BN_d, BN_d, BN_d, BN_d, BN_d, BN_d, BN_d, BN_d };
    const BIGNUM* pa_prv_k[MBX_LANES] = { BN_k, BN_k, BN_k, BN_k, BN_k, BN_k, BN_k, BN_k };
    // output signature
    int8u* pa_sign_r[MBX_LANES] = { out_r[0], out_r[1], out_r[2], out_r[3],
                                    out_r[4], out_r[5], out_r[6], out_r[7] };
    int8u* pa_sign_s[MBX_LANES] = { out_s[0], out_s[1], out_s[2], out_s[3],
                                    out_s[4], out_s[5], out_s[6], out_s[7] };

    /* test function */
    mbx_status sts;
    sts = mbx_nistp384_ecdsa_sign_ssl_mb8(
        pa_sign_r, pa_sign_s, pa_pub_msg_digest, pa_prv_k, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output signature to known answer
    int r_output_status;
    int s_output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        r_output_status =
            mbx_is_mem_eq(pa_sign_r[i], MBX_NISTP384_DATA_BYTE_LEN, r, MBX_NISTP384_DATA_BYTE_LEN);
        s_output_status =
            mbx_is_mem_eq(pa_sign_s[i], MBX_NISTP384_DATA_BYTE_LEN, s, MBX_NISTP384_DATA_BYTE_LEN);
        if (!r_output_status || !s_output_status) { // wrong output
            test_result = MBX_ALGO_SELFTEST_KAT_ERR;
        }
    }

    // memory free
    MEM_FREE(BN_d, BN_k)

    return test_result;
}

#endif // BN_OPENSSL_DISABLE
#endif // MBX_FIPS_MODE
