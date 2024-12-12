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

/* KAT TEST (taken from wycheproof testing) */
/* public */
static const int8u pub_x[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x26, 0x4f, 0xe4, 0xaf, 0x31, 0xd7, 0x61, 0xfa, 0xfd, 0x0b, 0x8b, 0x86, 0x46, 0x70, 0xe0, 0x28,
    0x24, 0x50, 0x0f, 0x5d, 0x71, 0x40, 0xa0, 0x85, 0xfe, 0x75, 0xaf, 0x72, 0x33, 0xbd, 0xd5, 0x62
};

static const int8u pub_y[MBX_NISTP256_DATA_BYTE_LEN] = {
    0xcf, 0x30, 0x4e, 0x01, 0x5a, 0x27, 0x7d, 0xa0, 0xb4, 0x72, 0x88, 0xc3, 0xc8, 0x41, 0xb7, 0x0e,
    0x99, 0x13, 0x8d, 0xbf, 0xb5, 0x95, 0x5a, 0xcd, 0x81, 0x0a, 0xe7, 0xa9, 0x93, 0x3a, 0x33, 0xac
};
/* private */
static const int8u prv_key[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x46, 0xc3, 0x10, 0x2c, 0xe0, 0x52, 0x53, 0x7b, 0x64, 0x38, 0x41, 0xf8, 0xae, 0x53, 0xbb, 0xfe,
    0xd3, 0xbf, 0xce, 0x6b, 0x0a, 0x5b, 0x85, 0x17, 0xab, 0x23, 0xa0, 0x89, 0x5c, 0x46, 0x12, 0x06
};
/* shared key */
static const int8u sh_key[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x53, 0x02, 0x0d, 0x90, 0x8b, 0x02, 0x19, 0x32, 0x8b, 0x65, 0x8b, 0x52, 0x5f, 0x26, 0x78, 0x0e,
    0x3a, 0xe1, 0x2b, 0xcd, 0x95, 0x2b, 0xb2, 0x5a, 0x93, 0xbc, 0x08, 0x95, 0xe1, 0x71, 0x42, 0x85
};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp256_ecdh_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* output shared key */
    int8u out_shared_key[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];

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
    sts         = mbx_nistp256_ecdh_mb8(pa_shared_key, pa_prv_key, pa_pub_x, pa_pub_y, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output shared key to known answer
    int output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        output_status = mbx_is_mem_eq(
            pa_shared_key[i], MBX_NISTP256_DATA_BYTE_LEN, sh_key, MBX_NISTP256_DATA_BYTE_LEN);
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
fips_test_status fips_selftest_mbx_nistp256_ecdh_ssl_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* output shared key */
    int8u out_shared_key[MBX_LANES][MBX_NISTP256_DATA_BYTE_LEN];
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

    // set ssl keys
    BN_lebin2bn(pub_x, MBX_NISTP256_DATA_BYTE_LEN, BN_pub_x);
    BN_lebin2bn(pub_y, MBX_NISTP256_DATA_BYTE_LEN, BN_pub_y);
    BN_lebin2bn(prv_key, MBX_NISTP256_DATA_BYTE_LEN, BN_prv_key);

    /* function input parameters */
    // output shared key
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
    sts = mbx_nistp256_ecdh_ssl_mb8(pa_shared_key, pa_prv_key, pa_pub_x, pa_pub_y, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output shared key to known answer
    int output_status;
    for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
        output_status = mbx_is_mem_eq(
            pa_shared_key[i], MBX_NISTP256_DATA_BYTE_LEN, sh_key, MBX_NISTP256_DATA_BYTE_LEN);
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
