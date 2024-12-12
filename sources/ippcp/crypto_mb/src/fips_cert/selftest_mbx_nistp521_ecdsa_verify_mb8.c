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

#ifndef BN_OPENSSL_DISABLE
#include <openssl/ecdsa.h>
#endif

/* KAT TEST (taken from FIPS 186-4 examples) */
// msg ==
// "f69417bead3b1e208c4c99236bf84474a00de7f0b9dd23f991b6b60ef0fb3c62"
// "073a5a7abb1ef69dbbd8cf61e64200ca086dfd645b641e8d02397782da92d354"
// "2fbddf6349ac0b48b1b1d69fe462d1bb492f34dd40d137163843ac11bd099df7"
// "19212c160cbebcb2ab6f3525e64846c887e1b52b52eced9447a3d31938593a87"

/* msgDigest == SHA-521(msg) */
static const int8u msg_digest[MBX_NISTP521_DATA_BYTE_LEN] = {
    0x00, 0x00, 0x97, 0xff, 0x5a, 0x81, 0xfc, 0x88, 0xf7, 0xdd, 0xd3, 0xbc, 0x58, 0x15,
    0x4f, 0xfd, 0x26, 0x95, 0x91, 0x2f, 0xe5, 0x0c, 0xe7, 0xc6, 0x3b, 0x62, 0xbd, 0x79,
    0x8f, 0xb6, 0x73, 0xc6, 0xaa, 0x49, 0xf5, 0x4b, 0xc7, 0x30, 0x1f, 0xb7, 0xbd, 0xdc,
    0x6e, 0xdc, 0x51, 0xb7, 0xe0, 0xd0, 0xb4, 0xde, 0xc9, 0xf8, 0x08, 0x51, 0xff, 0xf0,
    0x2a, 0x33, 0x67, 0x1a, 0xd9, 0xa4, 0x06, 0xbb, 0xab, 0xe5
};
/* public key */
static const int8u Qx[MBX_NISTP521_DATA_BYTE_LEN] = {
    0x67, 0x48, 0x03, 0x48, 0xc4, 0xb9, 0xcf, 0xc7, 0x28, 0xc7, 0xcd, 0x00, 0x8e, 0xa6,
    0x1f, 0x7a, 0x5c, 0xf1, 0xa5, 0x44, 0x15, 0x87, 0x09, 0xcd, 0x6b, 0x65, 0x06, 0x6a,
    0x94, 0xdc, 0x80, 0x88, 0x0d, 0x4a, 0x39, 0x26, 0xee, 0x3e, 0x69, 0x4b, 0xc1, 0x9c,
    0xbc, 0xf0, 0x19, 0xbf, 0x7c, 0x92, 0x3b, 0x84, 0xc2, 0xef, 0x13, 0xb4, 0x41, 0xfb,
    0xef, 0xc1, 0xe5, 0x38, 0x54, 0xe0, 0x2b, 0xeb, 0x53, 0x01
};

static const int8u Qy[MBX_NISTP521_DATA_BYTE_LEN] = {
    0xc1, 0x9b, 0xef, 0x3e, 0x23, 0x89, 0xbb, 0x49, 0xc0, 0x2d, 0x87, 0xc0, 0xf0, 0x3e,
    0x03, 0x47, 0xfa, 0xa4, 0x2f, 0x1f, 0xd8, 0x22, 0x05, 0xec, 0xd0, 0xdd, 0x38, 0xf3,
    0x29, 0x79, 0x4e, 0x37, 0xe3, 0xec, 0xd5, 0x9e, 0x51, 0xb7, 0x11, 0x73, 0x31, 0x09,
    0x8c, 0x87, 0x1d, 0x7c, 0xc1, 0x32, 0xeb, 0x9c, 0x0a, 0x97, 0xb2, 0x59, 0x61, 0x6e,
    0xb1, 0xf6, 0xfc, 0xe8, 0xbc, 0xec, 0x8e, 0xae, 0x43, 0x01
};
/* signature */
static const int8u r[MBX_NISTP521_DATA_BYTE_LEN] = {
    0x00, 0xdd, 0x63, 0x39, 0x47, 0x44, 0x6d, 0x0d, 0x51, 0xa9, 0x6a, 0x01, 0x73, 0xc0,
    0x11, 0x25, 0x85, 0x8a, 0xbb, 0x2b, 0xec, 0xe6, 0x70, 0xaf, 0x92, 0x2a, 0x92, 0xde,
    0xdc, 0xec, 0x06, 0x71, 0x36, 0xc1, 0xfa, 0x92, 0xe5, 0xfa, 0x73, 0xd7, 0x11, 0x6a,
    0xc9, 0xc1, 0xa4, 0x2b, 0x9c, 0xb6, 0x42, 0xe4, 0xac, 0x19, 0x31, 0x0b, 0x04, 0x9e,
    0x48, 0xc5, 0x30, 0x11, 0xff, 0xc6, 0xe7, 0x46, 0x1c, 0x36
};

static const int8u s[MBX_NISTP521_DATA_BYTE_LEN] = {
    0x00, 0xef, 0xbd, 0xc6, 0xa4, 0x14, 0xbb, 0x8d, 0x66, 0x3b, 0xb5, 0xcd, 0xb7, 0xc5,
    0x86, 0xbc, 0xcf, 0xe7, 0x58, 0x90, 0x49, 0x07, 0x6f, 0x98, 0xce, 0xe8, 0x2c, 0xdb,
    0x5d, 0x20, 0x3f, 0xdd, 0xb2, 0xe0, 0xff, 0xb7, 0x79, 0x54, 0x95, 0x9d, 0xfa, 0x5e,
    0xd0, 0xde, 0x85, 0x0e, 0x42, 0xa8, 0x6f, 0x5a, 0x63, 0xc5, 0xa6, 0x59, 0x2e, 0x9b,
    0x9b, 0x8b, 0xd1, 0xb4, 0x05, 0x57, 0xb9, 0xcd, 0x0c, 0xc0
};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp521_ecdsa_verify_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* function input parameters */
    // msg digest
    const int8u* const pa_pub_msg_digest[MBX_LANES] = { msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest };
    // public key
    const int64u* const pa_pub_Qx[MBX_LANES] = { (const int64u* const)Qx, (const int64u* const)Qx,
                                                 (const int64u* const)Qx, (const int64u* const)Qx,
                                                 (const int64u* const)Qx, (const int64u* const)Qx,
                                                 (const int64u* const)Qx, (const int64u* const)Qx };
    const int64u* const pa_pub_Qy[MBX_LANES] = { (const int64u* const)Qy, (const int64u* const)Qy,
                                                 (const int64u* const)Qy, (const int64u* const)Qy,
                                                 (const int64u* const)Qy, (const int64u* const)Qy,
                                                 (const int64u* const)Qy, (const int64u* const)Qy };
    // signature
    const int8u* const pa_sign_r[MBX_LANES] = { r, r, r, r, r, r, r, r };
    const int8u* const pa_sign_s[MBX_LANES] = { s, s, s, s, s, s, s, s };

    /* test function */
    mbx_status sts;
    sts = mbx_nistp521_ecdsa_verify_mb8(
        pa_sign_r, pa_sign_s, pa_pub_msg_digest, pa_pub_Qx, pa_pub_Qy, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_KAT_ERR);

    return test_result;
}

#ifndef BN_OPENSSL_DISABLE

#define MEM_FREE(BN_PTR1, BN_PTR2, SIG_PTR1) \
    {                                        \
        BN_free(BN_PTR1);                    \
        BN_free(BN_PTR2);                    \
        ECDSA_SIG_free(SIG_PTR1);            \
    }

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp521_ecdsa_verify_ssl_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* ssl public key */
    BIGNUM* BN_Qx = BN_new();
    BIGNUM* BN_Qy = BN_new();

    // set ssl public key
    BN_lebin2bn(Qx, MBX_NISTP521_DATA_BYTE_LEN, BN_Qx);
    BN_lebin2bn(Qy, MBX_NISTP521_DATA_BYTE_LEN, BN_Qy);

    // set ssl signature
    BIGNUM* BN_r   = BN_new();
    BIGNUM* BN_s   = BN_new();
    ECDSA_SIG* sig = ECDSA_SIG_new();
    /* check if allocated memory is valid */
    if (NULL == BN_Qx || NULL == BN_Qy || NULL == BN_r || NULL == BN_s || NULL == sig) {
        test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
        MEM_FREE(BN_Qx, BN_Qy, sig)
        // Handled separately, since memory management of
        // these variables is transferred to sig below
        BN_free(BN_r);
        BN_free(BN_s);
        return test_result;
    }

    BN_bin2bn(r, MBX_NISTP521_DATA_BYTE_LEN, BN_r);
    BN_bin2bn(s, MBX_NISTP521_DATA_BYTE_LEN, BN_s);
    ECDSA_SIG_set0(sig, BN_r, BN_s);

    /* function input parameters */
    // msg digest
    const int8u* const pa_pub_msg_digest[MBX_LANES] = { msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest, msg_digest,
                                                        msg_digest, msg_digest };
    // public key
    const BIGNUM* const pa_pub_Qx[MBX_LANES] = { BN_Qx, BN_Qx, BN_Qx, BN_Qx,
                                                 BN_Qx, BN_Qx, BN_Qx, BN_Qx };
    const BIGNUM* const pa_pub_Qy[MBX_LANES] = { BN_Qy, BN_Qy, BN_Qy, BN_Qy,
                                                 BN_Qy, BN_Qy, BN_Qy, BN_Qy };
    // signature
    const ECDSA_SIG* const pa_sig[MBX_LANES] = { sig, sig, sig, sig, sig, sig, sig, sig };

    /* test function */
    mbx_status sts;
    sts = mbx_nistp521_ecdsa_verify_ssl_mb8(
        pa_sig, pa_pub_msg_digest, pa_pub_Qx, pa_pub_Qy, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_KAT_ERR);

    // memory free
    BN_free(BN_Qx);
    BN_free(BN_Qy);
    ECDSA_SIG_free(sig);

    return test_result;
}

#endif // BN_OPENSSL_DISABLE
#endif // MBX_FIPS_MODE
