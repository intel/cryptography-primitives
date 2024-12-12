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

#include <crypto_mb/ec_nistp384.h>
#include <crypto_mb/fips_cert.h>

#include <internal/fips_cert/common.h>

#ifndef BN_OPENSSL_DISABLE
#include <openssl/ecdsa.h>
#endif

/* KAT TEST (taken from FIPS 186-4 examples) */
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
/* public key */
static const int8u Qx[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x44, 0xf1, 0x9a, 0xfd, 0x64, 0xd0, 0xd7, 0x37, 0xef, 0x0f, 0xe0, 0x23, 0xfb, 0x78, 0xbd, 0x75,
    0x1d, 0x95, 0xd1, 0x95, 0x51, 0x76, 0xb3, 0xe2, 0x35, 0x50, 0x0c, 0xe2, 0xec, 0x4f, 0x15, 0xcb,
    0x33, 0x9b, 0x57, 0x83, 0x43, 0xe1, 0xe1, 0x8e, 0x7b, 0xa5, 0x16, 0xd5, 0x1f, 0x8b, 0x90, 0xcb
};

static const int8u Qy[MBX_NISTP384_DATA_BYTE_LEN] = {
    0xbb, 0x74, 0xc3, 0xf7, 0xfd, 0xbd, 0x83, 0x95, 0xa0, 0xca, 0xdb, 0x2a, 0xe3, 0xfb, 0x9b, 0xf7,
    0x60, 0xc3, 0xb2, 0x59, 0x6f, 0x1f, 0x55, 0x8c, 0xed, 0x1b, 0x01, 0x9a, 0xad, 0xcb, 0xf1, 0xfa,
    0x21, 0x21, 0x82, 0xcf, 0xf7, 0x2c, 0xff, 0xdc, 0x1d, 0x40, 0x57, 0x58, 0x6b, 0xc4, 0x99, 0xcd
};
/* signature */
static const int8u r[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x33, 0xf6, 0x4f, 0xb6, 0x5c, 0xd6, 0xa8, 0x91, 0x85, 0x23, 0xf2, 0x3a, 0xea, 0x0b, 0xbc, 0xf5,
    0x6b, 0xba, 0x1d, 0xac, 0xa7, 0xaf, 0xf8, 0x17, 0xc8, 0x79, 0x1d, 0xc9, 0x24, 0x28, 0xd6, 0x05,
    0xac, 0x62, 0x9d, 0xe2, 0xe8, 0x47, 0xd4, 0x3c, 0xee, 0x55, 0xba, 0x9e, 0x4a, 0x0e, 0x83, 0xba
};

static const int8u s[MBX_NISTP384_DATA_BYTE_LEN] = {
    0x44, 0x28, 0xbb, 0x47, 0x8a, 0x43, 0xac, 0x73, 0xec, 0xd6, 0xde, 0x51, 0xdd, 0xf7, 0xc2, 0x8f,
    0xf3, 0xc2, 0x44, 0x16, 0x25, 0xa0, 0x81, 0x71, 0x43, 0x37, 0xdd, 0x44, 0xfe, 0xa8, 0x01, 0x1b,
    0xae, 0x71, 0x95, 0x9a, 0x10, 0x94, 0x7b, 0x6e, 0xa3, 0x3f, 0x77, 0xe1, 0x28, 0xd3, 0xc6, 0xae
};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp384_ecdsa_verify_mb8(void)
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
    sts = mbx_nistp384_ecdsa_verify_mb8(
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
fips_test_status fips_selftest_mbx_nistp384_ecdsa_verify_ssl_mb8(void)
{
    fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

    /* ssl public key */
    BIGNUM* BN_Qx = BN_new();
    BIGNUM* BN_Qy = BN_new();

    // ssl signature
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

    // set ssl public key
    BN_lebin2bn(Qx, MBX_NISTP384_DATA_BYTE_LEN, BN_Qx);
    BN_lebin2bn(Qy, MBX_NISTP384_DATA_BYTE_LEN, BN_Qy);
    // set ssl signature
    BN_bin2bn(r, MBX_NISTP384_DATA_BYTE_LEN, BN_r);
    BN_bin2bn(s, MBX_NISTP384_DATA_BYTE_LEN, BN_s);
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
    sts = mbx_nistp384_ecdsa_verify_ssl_mb8(
        pa_sig, pa_pub_msg_digest, pa_pub_Qx, pa_pub_Qy, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_KAT_ERR);

    // memory free
    MEM_FREE(BN_Qx, BN_Qy, sig)

    return test_result;
}

#endif // BN_OPENSSL_DISABLE
#endif // MBX_FIPS_MODE
