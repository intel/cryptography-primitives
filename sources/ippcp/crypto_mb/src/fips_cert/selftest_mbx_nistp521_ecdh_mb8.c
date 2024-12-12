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

#include <crypto_mb/ec_nistp521.h>

/* KAT TEST (taken from wycheproof testing) */
/* public */
static const int8u pub_x[MBX_NISTP521_DATA_BYTE_LEN] = {
    0xce, 0xb5, 0x99, 0x79, 0x07, 0xf3, 0x3c, 0x61, 0xf1, 0xad, 0x51, 0x72, 0x33, 0x92,
    0xf4, 0xe7, 0x52, 0xa6, 0x91, 0x48, 0x44, 0x6d, 0x92, 0x42, 0x26, 0x97, 0x4c, 0x2d,
    0xdf, 0x2b, 0xca, 0x69, 0x97, 0xd7, 0xd9, 0x75, 0x85, 0xd3, 0xfb, 0x77, 0x83, 0x19,
    0x9a, 0x52, 0xa6, 0x1d, 0x4a, 0xc5, 0x31, 0x5a, 0x26, 0xb2, 0x5c, 0x8a, 0x0d, 0x4a,
    0xa7, 0x36, 0xb5, 0x3d, 0x73, 0x94, 0x3e, 0xda, 0x64, 0x00
};

static const int8u pub_y[MBX_NISTP521_DATA_BYTE_LEN] = {
    0xf7, 0x98, 0xa0, 0xab, 0xc5, 0x70, 0x0a, 0xa9, 0x63, 0xbb, 0x46, 0x33, 0x16, 0x50,
    0x59, 0xfc, 0xdb, 0xb6, 0x5b, 0xb8, 0x38, 0xf3, 0xdd, 0x09, 0x14, 0xdb, 0x54, 0xfb,
    0x5a, 0x37, 0xed, 0x3c, 0x18, 0x79, 0x4f, 0x4a, 0xae, 0x52, 0x21, 0x42, 0x92, 0xfa,
    0x0d, 0x94, 0x88, 0x52, 0xbc, 0x7e, 0x0e, 0x3c, 0x0c, 0xf7, 0x69, 0xc0, 0x24, 0xc8,
    0xb0, 0x22, 0x47, 0xfd, 0xf9, 0x9c, 0xd1, 0x4a, 0xe0, 0x00
};
/* private */
static const int8u prv_key[MBX_NISTP521_DATA_BYTE_LEN] = {
    0xcd, 0x7d, 0x1c, 0x61, 0x1f, 0x37, 0xa7, 0x40, 0x44, 0x57, 0x58, 0xd4, 0x41, 0x13,
    0x4a, 0xe3, 0x2a, 0x99, 0x43, 0xdf, 0xc6, 0x6d, 0x56, 0x64, 0x5b, 0x79, 0x8f, 0x59,
    0x0d, 0xc9, 0x40, 0x16, 0xc6, 0xe7, 0x22, 0xbb, 0xc9, 0xef, 0x06, 0xd5, 0x19, 0xf6,
    0xb8, 0x87, 0x4f, 0xeb, 0x49, 0xa8, 0x21, 0x2c, 0xe9, 0x03, 0xfd, 0x6e, 0xbc, 0x94,
    0x7a, 0xe7, 0x6c, 0x59, 0x29, 0xb5, 0x82, 0x99, 0x93, 0x01
};
/* shared key */
static const int8u sh_key[MBX_NISTP521_DATA_BYTE_LEN] = {
    0x01, 0xf1, 0xe4, 0x10, 0xf2, 0xc6, 0x26, 0x2b, 0xce, 0x68, 0x79, 0xa3, 0xf4, 0x6d,
    0xfb, 0x7d, 0xd1, 0x1d, 0x30, 0xee, 0xee, 0x9a, 0xb4, 0x98, 0x52, 0x10, 0x2e, 0x18,
    0x92, 0x20, 0x1d, 0xd1, 0x0f, 0x27, 0x26, 0x6c, 0x2c, 0xf7, 0xcb, 0xcc, 0xc7, 0xf6,
    0x88, 0x50, 0x99, 0x04, 0x3d, 0xad, 0x80, 0xff, 0x57, 0xf0, 0xdf, 0x96, 0xac, 0xf2,
    0x83, 0xfb, 0x09, 0x0d, 0xe5, 0x3d, 0xf9, 0x5f, 0x7d, 0x87
};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp521_ecdh_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* output shared key */
    int8u out_shared_key[MBX_LANES][MBX_NISTP521_DATA_BYTE_LEN];

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
    sts         = mbx_nistp521_ecdh_mb8(pa_shared_key, pa_prv_key, pa_pub_x, pa_pub_y, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output shared key to known answer
    int output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        output_status = mbx_is_mem_eq(
            pa_shared_key[i], MBX_NISTP521_DATA_BYTE_LEN, sh_key, MBX_NISTP521_DATA_BYTE_LEN);
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
fips_test_status fips_selftest_mbx_nistp521_ecdh_ssl_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* output shared key */
    int8u out_shared_key[MBX_LANES][MBX_NISTP521_DATA_BYTE_LEN];
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
    BN_lebin2bn(pub_x, MBX_NISTP521_DATA_BYTE_LEN, BN_pub_x);
    BN_lebin2bn(pub_y, MBX_NISTP521_DATA_BYTE_LEN, BN_pub_y);
    BN_lebin2bn(prv_key, MBX_NISTP521_DATA_BYTE_LEN, BN_prv_key);

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
    sts = mbx_nistp521_ecdh_ssl_mb8(pa_shared_key, pa_prv_key, pa_pub_x, pa_pub_y, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output shared key to known answer
    int output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        output_status = mbx_is_mem_eq(
            pa_shared_key[i], MBX_NISTP521_DATA_BYTE_LEN, sh_key, MBX_NISTP521_DATA_BYTE_LEN);
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
