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

/* Pairwise Consistency Test for ED25519 keypair */
/* KAT data taken from wycheproof testing */
/* msg len */
#define MSG_LEN (16)
/* msg */
static const int8u msg[MSG_LEN] = { 0 };
/* output public key */
static ed25519_public_key out_pub_key[MBX_LANES];
/* output signature */
static ed25519_sign_component out_r[MBX_LANES];
static ed25519_sign_component out_s[MBX_LANES];
/* private key */
static const ed25519_private_key prv_key = { 0xad, 0xd4, 0xbb, 0x81, 0x03, 0x78, 0x5b, 0xaf,
                                             0x9a, 0xc5, 0x34, 0x25, 0x8e, 0x8a, 0xaf, 0x65,
                                             0xf5, 0xf1, 0xad, 0xb5, 0xef, 0x5f, 0x3d, 0xf1,
                                             0x9b, 0xb8, 0x0a, 0xb9, 0x89, 0xc4, 0xd6, 0x4b };


DLL_PUBLIC
fips_test_status fips_selftest_mbx_ed25519_public_key_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* functions input parameters */
    // msg
    const int8u* const pa_msg[MBX_LANES] = { msg, msg, msg, msg, msg, msg, msg, msg };
    // msg len
    const int32u pa_msg_len[MBX_LANES] = { MSG_LEN, MSG_LEN, MSG_LEN, MSG_LEN,
                                           MSG_LEN, MSG_LEN, MSG_LEN, MSG_LEN };
    // private key
    const ed25519_private_key* const pa_prv_key[MBX_LANES] = {
        (const ed25519_private_key* const)prv_key, (const ed25519_private_key* const)prv_key,
        (const ed25519_private_key* const)prv_key, (const ed25519_private_key* const)prv_key,
        (const ed25519_private_key* const)prv_key, (const ed25519_private_key* const)prv_key,
        (const ed25519_private_key* const)prv_key, (const ed25519_private_key* const)prv_key
    };

    /* functions output parameters */
    // output public key
    ed25519_public_key* pa_out_pub_key[MBX_LANES] = {
        (ed25519_public_key*)out_pub_key[0], (ed25519_public_key*)out_pub_key[1],
        (ed25519_public_key*)out_pub_key[2], (ed25519_public_key*)out_pub_key[3],
        (ed25519_public_key*)out_pub_key[4], (ed25519_public_key*)out_pub_key[5],
        (ed25519_public_key*)out_pub_key[6], (ed25519_public_key*)out_pub_key[7]
    };
    // output signature components
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

    /* test functions */
    // generate public key
    mbx_status sts;
    sts         = mbx_ed25519_public_key_mb8(pa_out_pub_key, pa_prv_key);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);
    if (test_result != MBX_ALGO_SELFTEST_OK) {
        return test_result;
    }

    // sign and verify with the generated keypair
    sts         = mbx_ed25519_sign_mb8(pa_sign_r,
                               pa_sign_s,
                               pa_msg,
                               pa_msg_len,
                               pa_prv_key,
                               (const ed25519_public_key* const*)pa_out_pub_key);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);
    if (test_result != MBX_ALGO_SELFTEST_OK) {
        return test_result;
    }

    sts = mbx_ed25519_verify_mb8((const ed25519_sign_component* const*)pa_sign_r,
                                 (const ed25519_sign_component* const*)pa_sign_s,
                                 pa_msg,
                                 pa_msg_len,
                                 (const ed25519_public_key* const*)pa_out_pub_key);

    // check the result of verification
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_KAT_ERR);

    return test_result;
}

#endif // MBX_FIPS_MODE
