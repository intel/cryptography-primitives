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

/* KAT TEST (taken from FIPS 186-4 examples) */
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
/* key pair */
static const int8u d[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x64, 0xb4, 0x72, 0xda, 0x6d, 0xa5, 0x54, 0xca, 0xac, 0x3e, 0x4e, 0x0b, 0x13, 0xc8, 0x44, 0x5b,
    0x1a, 0x77, 0xf4, 0x59, 0xee, 0xa8, 0x4f, 0x1f, 0x58, 0x8b, 0x5f, 0x71, 0x3d, 0x42, 0x9b, 0x51
};

static const int8u k[MBX_NISTP256_DATA_BYTE_LEN] = {
    0xde, 0x68, 0x2a, 0x64, 0x87, 0x07, 0x67, 0xb9, 0x33, 0x5d, 0x4f, 0x82, 0x47, 0x62, 0x4a, 0x3b,
    0x7f, 0x3c, 0xe9, 0xf9, 0x45, 0xf2, 0x80, 0xa2, 0x61, 0x6a, 0x90, 0x4b, 0xb1, 0xbb, 0xa1, 0x94
};
/* signature */
static const int8u r[MBX_NISTP256_DATA_BYTE_LEN] = {
    0xf3, 0xac, 0x80, 0x61, 0xb5, 0x14, 0x79, 0x5b, 0x88, 0x43, 0xe3, 0xd6, 0x62, 0x95, 0x27, 0xed,
    0x2a, 0xfd, 0x6b, 0x1f, 0x6a, 0x55, 0x5a, 0x7a, 0xca, 0xbb, 0x5e, 0x6f, 0x79, 0xc8, 0xc2, 0xac
};

static const int8u s[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x8b, 0xf7, 0x78, 0x19, 0xca, 0x05, 0xa6, 0xb2, 0x78, 0x6c, 0x76, 0x26, 0x2b, 0xf7, 0x37, 0x1c,
    0xef, 0x97, 0xb2, 0x18, 0xe9, 0x6f, 0x17, 0x5a, 0x3c, 0xcd, 0xda, 0x2a, 0xcc, 0x05, 0x89, 0x03
};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp256_ecdsa_sign_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* output signature */
    int8u out_r[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];
    int8u out_s[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];

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
    sts = mbx_nistp256_ecdsa_sign_mb8(
        pa_sign_r, pa_sign_s, pa_pub_msg_digest, pa_prv_k, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output signature to known answer
    int r_output_status;
    int s_output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        r_output_status =
            mbx_is_mem_eq(pa_sign_r[i], MBX_NISTP256_DATA_BYTE_LEN, r, MBX_NISTP256_DATA_BYTE_LEN);
        s_output_status =
            mbx_is_mem_eq(pa_sign_s[i], MBX_NISTP256_DATA_BYTE_LEN, s, MBX_NISTP256_DATA_BYTE_LEN);
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
fips_test_status fips_selftest_mbx_nistp256_ecdsa_sign_ssl_mb8(void)
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
    int8u out_r[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];
    int8u out_s[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];

    // set ssl key pair
    BN_lebin2bn(d, MBX_NISTP256_DATA_BYTE_LEN, BN_d);
    BN_lebin2bn(k, MBX_NISTP256_DATA_BYTE_LEN, BN_k);

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
    sts = mbx_nistp256_ecdsa_sign_ssl_mb8(
        pa_sign_r, pa_sign_s, pa_pub_msg_digest, pa_prv_k, pa_prv_d, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output signature to known answer
    int r_output_status;
    int s_output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        r_output_status =
            mbx_is_mem_eq(pa_sign_r[i], MBX_NISTP256_DATA_BYTE_LEN, r, MBX_NISTP256_DATA_BYTE_LEN);
        s_output_status =
            mbx_is_mem_eq(pa_sign_s[i], MBX_NISTP256_DATA_BYTE_LEN, s, MBX_NISTP256_DATA_BYTE_LEN);
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
