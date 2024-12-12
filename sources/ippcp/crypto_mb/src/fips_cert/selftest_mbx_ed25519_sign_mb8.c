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

#include <crypto_mb/ed25519.h>

/* KAT TEST (taken from wycheproof testing) */
/* msg len */
static const int32u msg_len = 0;
/* msg */
static const int8u msg[] = { 0 };
/* public key */
static const ed25519_public_key pub_key = { 0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b,
                                            0x62, 0x42, 0xb5, 0x22, 0xab, 0xbe, 0xe6, 0x85,
                                            0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34, 0xb1, 0x08,
                                            0xc3, 0xbd, 0xae, 0x36, 0x9e, 0xf5, 0x49, 0xfa };
/* private key */
static const ed25519_private_key prv_key = { 0xad, 0xd4, 0xbb, 0x81, 0x03, 0x78, 0x5b, 0xaf,
                                             0x9a, 0xc5, 0x34, 0x25, 0x8e, 0x8a, 0xaf, 0x65,
                                             0xf5, 0xf1, 0xad, 0xb5, 0xef, 0x5f, 0x3d, 0xf1,
                                             0x9b, 0xb8, 0x0a, 0xb9, 0x89, 0xc4, 0xd6, 0x4b };
/* signature */
static const ed25519_sign_component r = { 0xd4, 0xfb, 0xdb, 0x52, 0xbf, 0xa7, 0x26, 0xb4,
                                          0x4d, 0x17, 0x86, 0xa8, 0xc0, 0xd1, 0x71, 0xc3,
                                          0xe6, 0x2c, 0xa8, 0x3c, 0x9e, 0x5b, 0xbe, 0x63,
                                          0xde, 0x0b, 0xb2, 0x48, 0x3f, 0x8f, 0xd6, 0xcc };

static const ed25519_sign_component s = { 0x14, 0x29, 0xab, 0x72, 0xca, 0xfc, 0x41, 0xab,
                                          0x56, 0xaf, 0x02, 0xff, 0x8f, 0xcc, 0x43, 0xb9,
                                          0x9b, 0xfe, 0x4c, 0x7a, 0xe9, 0x40, 0xf6, 0x0f,
                                          0x38, 0xeb, 0xaa, 0x9d, 0x31, 0x1c, 0x40, 0x07 };


DLL_PUBLIC
fips_test_status fips_selftest_mbx_ed25519_sign_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* output signature */
    ed25519_sign_component out_r[MBX_LANES];
    ed25519_sign_component out_s[MBX_LANES];

    /* function input parameters */
    // msg
    const int8u* const pa_msg[MBX_LANES] = { msg, msg, msg, msg, msg, msg, msg, msg };
    // msg len
    const int32u pa_msg_len[MBX_LANES] = { msg_len, msg_len, msg_len, msg_len,
                                           msg_len, msg_len, msg_len, msg_len };
    // public key
    const ed25519_public_key* const pa_pub_key[MBX_LANES] = {
        (const ed25519_public_key* const)pub_key, (const ed25519_public_key* const)pub_key,
        (const ed25519_public_key* const)pub_key, (const ed25519_public_key* const)pub_key,
        (const ed25519_public_key* const)pub_key, (const ed25519_public_key* const)pub_key,
        (const ed25519_public_key* const)pub_key, (const ed25519_public_key* const)pub_key
    };
    // private key
    const ed25519_private_key* const pa_prv_key[MBX_LANES] = {
        (const ed25519_private_key* const)prv_key, (const ed25519_private_key* const)prv_key,
        (const ed25519_private_key* const)prv_key, (const ed25519_private_key* const)prv_key,
        (const ed25519_private_key* const)prv_key, (const ed25519_private_key* const)prv_key,
        (const ed25519_private_key* const)prv_key, (const ed25519_private_key* const)prv_key
    };
    // output signature
    ed25519_sign_component* pa_sign_r[MBX_LANES] = {
        (ed25519_sign_component*)out_r[0], (ed25519_sign_component*)out_r[1],
        (ed25519_sign_component*)out_r[2], (ed25519_sign_component*)out_r[3],
        (ed25519_sign_component*)out_r[4], (ed25519_sign_component*)out_r[5],
        (ed25519_sign_component*)out_r[6], (ed25519_sign_component*)out_r[7]
    };
    ed25519_sign_component* pa_sign_s[MBX_LANES] = {
        (ed25519_sign_component*)out_s[0], (ed25519_sign_component*)out_s[1],
        (ed25519_sign_component*)out_s[2], (ed25519_sign_component*)out_s[3],
        (ed25519_sign_component*)out_s[4], (ed25519_sign_component*)out_s[5],
        (ed25519_sign_component*)out_s[6], (ed25519_sign_component*)out_s[7]
    };

    /* test function */
    mbx_status sts;
    sts = mbx_ed25519_sign_mb8(pa_sign_r, pa_sign_s, pa_msg, pa_msg_len, pa_prv_key, pa_pub_key);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

    // compare output signature to known answer
    int r_output_status;
    int s_output_status;
    for (int j = 0; (j < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++j) {
        r_output_status = mbx_is_mem_eq((const int8u*)pa_sign_r[j],
                                        MBX_ED25519_DATA_BYTE_LEN,
                                        (const int8u*)r,
                                        MBX_ED25519_DATA_BYTE_LEN);
        s_output_status = mbx_is_mem_eq((const int8u*)pa_sign_s[j],
                                        MBX_ED25519_DATA_BYTE_LEN,
                                        (const int8u*)s,
                                        MBX_ED25519_DATA_BYTE_LEN);
        if (!r_output_status || !s_output_status) { // wrong output
            test_result = MBX_ALGO_SELFTEST_KAT_ERR;
        }
    }

    return test_result;
}

#endif // MBX_FIPS_MODE
