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

#include <crypto_mb/ec_nistp256.h>
#include <crypto_mb/fips_cert.h>

#include <internal/fips_cert/common.h>

#ifndef BN_OPENSSL_DISABLE
#include <openssl/ecdsa.h>
#endif

/* KAT TEST (taken from FIPS 186-4 examples) */
// msg ==
// "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45f"
// "d75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217"
// "ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce4"
// "70a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3"

/* msgDigest == SHA-256(msg) */
static const int8u msg_digest[MBX_NISTP256_DATA_BYTE_LEN] = {
    0xd1, 0xb8, 0xef, 0x21, 0xeb, 0x41, 0x82, 0xee, 0x27, 0x06, 0x38, 0x06, 0x10, 0x63, 0xa3, 0xf3,
    0xc1, 0x6c, 0x11, 0x4e, 0x33, 0x93, 0x7f, 0x69, 0xfb, 0x23, 0x2c, 0xc8, 0x33, 0x96, 0x5a, 0x94
};
/* public key */
static const int8u Qx[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x3c, 0xbf, 0x9a, 0xf4, 0x12, 0x6e, 0x2e, 0xf8, 0x74, 0xc0, 0x67, 0x7a, 0x6f, 0xe1, 0x34, 0x51,
    0x0c, 0x7a, 0x95, 0xf8, 0xa7, 0x44, 0x43, 0xef, 0xb7, 0x3c, 0xbb, 0xd4, 0x61, 0xdc, 0x24, 0xe4
};

static const int8u Qy[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x27, 0xe9, 0xae, 0xdf, 0xe7, 0x60, 0x6f, 0x3d, 0x24, 0xd1, 0x85, 0xac, 0x65, 0x59, 0x7e, 0x12,
    0xf0, 0xda, 0xdd, 0xe1, 0x9d, 0x94, 0x45, 0x15, 0x65, 0x48, 0xbc, 0xa2, 0x7a, 0xed, 0x0e, 0x97
};
/* signature */
static const int8u r[MBX_NISTP256_DATA_BYTE_LEN] = {
    0xbf, 0x96, 0xb9, 0x9a, 0xa4, 0x9c, 0x70, 0x5c, 0x91, 0x0b, 0xe3, 0x31, 0x42, 0x01, 0x7c, 0x64,
    0x2f, 0xf5, 0x40, 0xc7, 0x63, 0x49, 0xb9, 0xda, 0xb7, 0x2f, 0x98, 0x1f, 0xd9, 0x34, 0x7f, 0x4f
};

static const int8u s[MBX_NISTP256_DATA_BYTE_LEN] = {
    0x17, 0xc5, 0x50, 0x95, 0x81, 0x90, 0x89, 0xc2, 0xe0, 0x3b, 0x9c, 0xd4, 0x15, 0xab, 0xdf, 0x12,
    0x44, 0x4e, 0x32, 0x30, 0x75, 0xd9, 0x8f, 0x31, 0x92, 0x0b, 0x9e, 0x0f, 0x57, 0xec, 0x87, 0x1c
};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_nistp256_ecdsa_verify_mb8(void)
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
    // KAT signature
    const int8u* const pa_sign_r[MBX_LANES] = { r, r, r, r, r, r, r, r };
    const int8u* const pa_sign_s[MBX_LANES] = { s, s, s, s, s, s, s, s };

    /* test function */
    mbx_status sts;
    sts = mbx_nistp256_ecdsa_verify_mb8(
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
fips_test_status fips_selftest_mbx_nistp256_ecdsa_verify_ssl_mb8(void)
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

    // set ssl public key and signature
    BN_lebin2bn(Qx, MBX_NISTP256_DATA_BYTE_LEN, BN_Qx);
    BN_lebin2bn(Qy, MBX_NISTP256_DATA_BYTE_LEN, BN_Qy);
    BN_bin2bn(r, MBX_NISTP256_DATA_BYTE_LEN, BN_r);
    BN_bin2bn(s, MBX_NISTP256_DATA_BYTE_LEN, BN_s);
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
    sts = mbx_nistp256_ecdsa_verify_ssl_mb8(
        pa_sig, pa_pub_msg_digest, pa_pub_Qx, pa_pub_Qy, NULL, NULL);
    test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_KAT_ERR);

    // memory free
    MEM_FREE(BN_Qx, BN_Qy, sig)

    return test_result;
}

#endif // BN_OPENSSL_DISABLE
#endif // MBX_FIPS_MODE
