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

/* KAT TEST (taken from wycheproof testing) */
/* public */
static const int8u pub_x[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x96, 0x87, 0x5d, 0x18, 0xd9, 0x2d, 0x01, 0xfa, 0x9f, 0x96, 0x15, 0xbe, 0xa6, 0x64, 0x1b, 0x79,
    0x4f, 0xb8, 0x7a, 0x67, 0xbf, 0xe8, 0x7e, 0xf1, 0xa2, 0x43, 0xfc, 0x43, 0x16, 0x79, 0x29, 0x5d,
    0x13, 0x09, 0x78, 0x4a, 0x3d, 0x18, 0x63, 0x01, 0x94, 0xa5, 0xf9, 0x9e, 0x05, 0x6e, 0x0a, 0x79
};

static const int8u pub_y[MBX_NISTP384_DATA_BYTE_LEN] = {
    0xaa, 0x3c, 0x16, 0xcb, 0xbf, 0xe5, 0xb5, 0xa0, 0x98, 0x1c, 0x5f, 0x02, 0x05, 0x67, 0x9a, 0x32,
    0x0d, 0x68, 0x1c, 0xcc, 0x1f, 0x8a, 0x30, 0xeb, 0x1a, 0x4b, 0x6b, 0xb2, 0xc3, 0x68, 0xf6, 0xb0,
    0xf6, 0xdf, 0xea, 0x56, 0x3b, 0x1b, 0x71, 0xdf, 0x82, 0x5e, 0xa7, 0xa8, 0xba, 0x54, 0xb9, 0xd9
};
/* private */
static const int8u prv_key[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x81, 0xfd, 0x5d, 0xb7, 0x88, 0xc5, 0x21, 0x9f, 0x6b, 0x35, 0x64, 0xdd, 0x4e, 0xee, 0x1d, 0xfb,
    0xd1, 0x9f, 0xc4, 0x48, 0xa9, 0x0d, 0xf2, 0x5b, 0x16, 0x85, 0xc7, 0x92, 0x73, 0x3b, 0x60, 0xf8,
    0xa6, 0x93, 0x4b, 0x56, 0xc3, 0x9f, 0xc0, 0x46, 0xf8, 0xa9, 0x2d, 0x5b, 0x42, 0x61, 0x6e, 0x76
};
/* shared key */
static const int8u sh_key[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x64, 0x61, 0xde, 0xfb, 0x95, 0xd9, 0x96, 0xb2, 0x42, 0x96, 0xf5, 0xa1, 0x83, 0x2b, 0x34, 0xdb,
    0x05, 0xed, 0x03, 0x11, 0x14, 0xfb, 0xe7, 0xd9, 0x8d, 0x09, 0x8f, 0x93, 0x85, 0x98, 0x66, 0xe4,
    0xde, 0x1e, 0x22, 0x9d, 0xa7, 0x1f, 0xef, 0x0c, 0x77, 0xfe, 0x49, 0xb2, 0x49, 0x19, 0x01, 0x35
};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp384_ecdh_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* output shared key */
    int8u out_shared_key[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];

    /* function input parameters */
    // shared
    int8u* pa_shared_key[MBX_LANES] = { out_shared_key[0], out_shared_key[1], out_shared_key[2],
                                        out_shared_key[3], out_shared_key[4], out_shared_key[5],
                                        out_shared_key[6], out_shared_key[7] };
    // private
    const int64u* pa_prv_key[MBX_LANES] = { (int64u*)prv_key, (int64u*)prv_key, (int64u*)prv_key,
                                            (int64u*)prv_key, (int64u*)prv_key, (int64u*)prv_key,
                                            (int64u*)prv_key, (int64u*)prv_key };
    // public
    const int64u* pa_pub_x[MBX_LANES] = { (int64u*)pub_x, (int64u*)pub_x, (int64u*)pub_x,
                                          (int64u*)pub_x, (int64u*)pub_x, (int64u*)pub_x,
                                          (int64u*)pub_x, (int64u*)pub_x };
    const int64u* pa_pub_y[MBX_LANES] = { (int64u*)pub_y, (int64u*)pub_y, (int64u*)pub_y,
                                          (int64u*)pub_y, (int64u*)pub_y, (int64u*)pub_y,
                                          (int64u*)pub_y, (int64u*)pub_y };

    /* test function */
    mbx_status sts;
    sts         = mbx_nistp384_ecdh_mb8(pa_shared_key, pa_prv_key, pa_pub_x, pa_pub_y, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output shared key to known answer
    int output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        output_status = mbx_is_mem_eq(
            pa_shared_key[i], MBX_NISTP384_DATA_BYTE_LEN, sh_key, MBX_NISTP384_DATA_BYTE_LEN);
        if (!output_status) { // wrong output
            test_result = MBX_ALGO_SELFTEST_KAT_ERR;
        }
    }

    return test_result;
}

#ifndef BN_OPENSSL_DISABLE

#define MEM_FREE(BN_PTR1, BN_PTR2, BN_PTR3) \
    {                                       \
        BN_free(BN_PTR1);                   \
        BN_free(BN_PTR2);                   \
        BN_free(BN_PTR3);                   \
    }

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp384_ecdh_ssl_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* output shared key */
    int8u out_shared_key[MBX_LANES][MBX_NISTP384_DATA_BYTE_LEN];
    /* ssl public key */
    BIGNUM* BN_pub_x = BN_new();
    BIGNUM* BN_pub_y = BN_new();
    /* ssl private key */
    BIGNUM* BN_prv_key = BN_new();
    /* check if allocated memory is valid */
    if (NULL == BN_pub_x || NULL == BN_pub_y || NULL == BN_prv_key) {
        test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
        MEM_FREE(BN_pub_x, BN_pub_y, BN_prv_key)
        return test_result;
    }

    /* set ssl keys */
    BN_lebin2bn(pub_x, MBX_NISTP384_DATA_BYTE_LEN, BN_pub_x);
    BN_lebin2bn(pub_y, MBX_NISTP384_DATA_BYTE_LEN, BN_pub_y);
    BN_lebin2bn(prv_key, MBX_NISTP384_DATA_BYTE_LEN, BN_prv_key);

    /* function input parameters */
    // shared
    int8u* pa_shared_key[MBX_LANES] = { out_shared_key[0], out_shared_key[1], out_shared_key[2],
                                        out_shared_key[3], out_shared_key[4], out_shared_key[5],
                                        out_shared_key[6], out_shared_key[7] };
    // private
    const BIGNUM* pa_prv_key[MBX_LANES] = { BN_prv_key, BN_prv_key, BN_prv_key, BN_prv_key,
                                            BN_prv_key, BN_prv_key, BN_prv_key, BN_prv_key };
    // public
    const BIGNUM* pa_pub_x[MBX_LANES] = { BN_pub_x, BN_pub_x, BN_pub_x, BN_pub_x,
                                          BN_pub_x, BN_pub_x, BN_pub_x, BN_pub_x };
    const BIGNUM* pa_pub_y[MBX_LANES] = { BN_pub_y, BN_pub_y, BN_pub_y, BN_pub_y,
                                          BN_pub_y, BN_pub_y, BN_pub_y, BN_pub_y };

    /* test function */
    mbx_status sts;
    sts = mbx_nistp384_ecdh_ssl_mb8(pa_shared_key, pa_prv_key, pa_pub_x, pa_pub_y, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output shared key to known answer
    int output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        output_status = mbx_is_mem_eq(
            pa_shared_key[i], MBX_NISTP384_DATA_BYTE_LEN, sh_key, MBX_NISTP384_DATA_BYTE_LEN);
        if (!output_status) { // wrong output
            test_result = MBX_ALGO_SELFTEST_KAT_ERR;
        }
    }

    // memory free
    MEM_FREE(BN_pub_x, BN_pub_y, BN_prv_key)

    return test_result;
}

#endif // BN_OPENSSL_DISABLE
#endif // MBX_FIPS_MODE
