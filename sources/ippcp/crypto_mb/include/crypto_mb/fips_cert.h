/*******************************************************************************
 * Copyright 2023 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

#ifndef CRYPTO_MB_FIPS_CERT_H
#define CRYPTO_MB_FIPS_CERT_H

#include <internal/common/ifma_defs.h>
#include <crypto_mb/status.h>

#define MBX_ALGO_SELFTEST_OK                  (0)
#define MBX_ALGO_SELFTEST_BAD_ARGS_ERR        (1)
#define MBX_ALGO_SELFTEST_KAT_ERR             (2)
#define MBX_ALGO_SELFTEST_UNSUPPORTED_ISA_ERR (4)

typedef int fips_test_status;
typedef int func_fips_approved;

EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecpublic_key_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecpublic_key_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecpublic_key_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecdh_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecdh_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecdh_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecdsa_sign_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecdsa_sign_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecdsa_sign_mb8(void);

/* mbx_nistp256_ecdsa_sign_setup_mb8() + mbx_nistp256_ecdsa_sign_complete_mb8() */
EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecdsa_sign_setup_complete_mb8(void);
/* mbx_nistp384_ecdsa_sign_setup_mb8() + mbx_nistp384_ecdsa_sign_complete_mb8() */
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecdsa_sign_setup_complete_mb8(void);
/* mbx_nistp521_ecdsa_sign_setup_mb8() + mbx_nistp521_ecdsa_sign_complete_mb8() */
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecdsa_sign_setup_complete_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecdsa_verify_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecdsa_verify_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecdsa_verify_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_ed25519_public_key_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_ed25519_sign_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_ed25519_verify_mb8(void);

/* x25519 scheme is not yet FIPS-approved */
// EXTERN_C fips_test_status fips_selftest_mbx_x25519_public_key_mb8(void);
// EXTERN_C fips_test_status fips_selftest_mbx_x25519_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_rsa2k_public_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa3k_public_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa4k_public_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_rsa2k_private_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa3k_private_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa4k_private_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_rsa2k_private_crt_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa3k_private_crt_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa4k_private_crt_mb8(void);

#ifndef BN_OPENSSL_DISABLE

EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecpublic_key_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecpublic_key_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecpublic_key_ssl_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecdh_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecdh_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecdh_ssl_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecdsa_sign_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecdsa_sign_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecdsa_sign_ssl_mb8(void);

/* mbx_nistp256_ecdsa_sign_setup_ssl_mb8() + mbx_nistp256_ecdsa_sign_complete_ssl_mb8() */
EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecdsa_sign_setup_complete_ssl_mb8(void);
/* mbx_nistp384_ecdsa_sign_setup_ssl_mb8() + mbx_nistp384_ecdsa_sign_complete_ssl_mb8() */
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecdsa_sign_setup_complete_ssl_mb8(void);
/* mbx_nistp521_ecdsa_sign_setup_ssl_mb8() + mbx_nistp521_ecdsa_sign_complete_ssl_mb8() */
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecdsa_sign_setup_complete_ssl_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_nistp256_ecdsa_verify_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp384_ecdsa_verify_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_nistp521_ecdsa_verify_ssl_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_rsa2k_public_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa3k_public_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa4k_public_ssl_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_rsa2k_private_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa3k_private_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa4k_private_ssl_mb8(void);

EXTERN_C fips_test_status fips_selftest_mbx_rsa2k_private_crt_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa3k_private_crt_ssl_mb8(void);
EXTERN_C fips_test_status fips_selftest_mbx_rsa4k_private_crt_ssl_mb8(void);

#endif // BN_OPEN_SSL_DISABLE

/*
// Enumerator that contains information about FIPS-approved
// functions inside the crypto_mb cryptographic boundary
*/
enum FIPS_CRYPTO_MB_FUNC {
    /* Approved functions, > 0 */
    nistp256_ecpublic_key_mb8 = 0x1,
    nistp384_ecpublic_key_mb8,
    nistp521_ecpublic_key_mb8,

    nistp256_ecdh_mb8,
    nistp384_ecdh_mb8,
    nistp521_ecdh_mb8,

    nistp256_ecdsa_sign_mb8,
    nistp384_ecdsa_sign_mb8,
    nistp521_ecdsa_sign_mb8,

    nistp256_ecdsa_sign_setup_mb8,
    nistp384_ecdsa_sign_setup_mb8,
    nistp521_ecdsa_sign_setup_mb8,

    nistp256_ecdsa_sign_complete_mb8,
    nistp384_ecdsa_sign_complete_mb8,
    nistp521_ecdsa_sign_complete_mb8,

    nistp256_ecdsa_verify_mb8,
    nistp384_ecdsa_verify_mb8,
    nistp521_ecdsa_verify_mb8,

    ed25519_public_key_mb8,
    ed25519_sign_mb8,
    ed25519_verify_mb8,

    rsa_public_mb8,
    rsa_private_mb8,
    rsa_private_crt_mb8,

    nistp256_ecpublic_key_ssl_mb8,
    nistp384_ecpublic_key_ssl_mb8,
    nistp521_ecpublic_key_ssl_mb8,

    nistp256_ecdh_ssl_mb8,
    nistp384_ecdh_ssl_mb8,
    nistp521_ecdh_ssl_mb8,

    nistp256_ecdsa_sign_ssl_mb8,
    nistp384_ecdsa_sign_ssl_mb8,
    nistp521_ecdsa_sign_ssl_mb8,

    nistp256_ecdsa_sign_setup_ssl_mb8,
    nistp384_ecdsa_sign_setup_ssl_mb8,
    nistp521_ecdsa_sign_setup_ssl_mb8,

    nistp256_ecdsa_sign_complete_ssl_mb8,
    nistp384_ecdsa_sign_complete_ssl_mb8,
    nistp521_ecdsa_sign_complete_ssl_mb8,

    nistp256_ecdsa_verify_ssl_mb8,
    nistp384_ecdsa_verify_ssl_mb8,
    nistp521_ecdsa_verify_ssl_mb8,

    rsa_public_ssl_mb8,
    rsa_private_ssl_mb8,
    rsa_private_crt_ssl_mb8,

    /* Not approved functions, < 0 */
    exp1024_mb8 = -0xFFF,
    exp2048_mb8,
    exp3072_mb8,
    exp4096_mb8,
    exp_mb8,

    x25519_public_key_mb8,
    x25519_mb8,

    sm2_ecpublic_key_mb8,
    sm2_ecdh_mb8,
    sm2_ecdsa_sign_mb8,
    sm2_ecdsa_verify_mb8,
    sm2_ecpublic_key_ssl_mb8,
    sm2_ecdh_ssl_mb8,
    sm2_ecdsa_sign_ssl_mb8,
    sm2_ecdsa_verify_ssl_mb8,

    sm3_init_mb16,
    sm3_update_mb16,
    sm3_final_mb16,
    sm3_msg_digest_mb16,

    sm4_set_key_mb16,
    sm4_encrypt_ecb_mb16,
    sm4_decrypt_ecb_mb16,
    sm4_encrypt_cbc_mb16,
    sm4_decrypt_cbc_mb16,
    sm4_encrypt_ctr128_mb16,
    sm4_decrypt_ctr128_mb16,
    sm4_encrypt_ofb_mb16,
    sm4_decrypt_ofb_mb16,
    sm4_encrypt_cfb128_mb16,
    sm4_decrypt_cfb128_mb16,

    sm4_gcm_init_mb16,
    sm4_gcm_update_iv_mb16,
    sm4_gcm_update_aad_mb16,
    sm4_gcm_encrypt_mb16,
    sm4_gcm_decrypt_mb16,
    sm4_gcm_get_tag_mb16,

    sm4_ccm_init_mb16,
    sm4_ccm_update_aad_mb16,
    sm4_ccm_encrypt_mb16,
    sm4_ccm_decrypt_mb16,
    sm4_ccm_get_tag_mb16,

    sm4_xts_set_keys_mb16,
    sm4_xts_encrypt_mb16,
    sm4_xts_decrypt_mb16,
};


/**
 * \brief
 *
 *  An indicator if a function is FIPS-approved or not
 *
 * \param[in] function              member of FIPS_CRYPTO_MB_FUNC enumerator
 *                                  that corresponds to API being checked.
 * \return    func_fips_approved    equal to 1 if FIPS-approved algorithm is used
 *
 * Example:
 *          Library API           FIPS_CRYPTO_MB_FUNC
 *       mbx_rsa_public_mb8   ->    rsa_public_mb8
 *     mbx_nistp256_ecdh_mb8  ->   nistp256_ecdh_mb8
 *      mbx_<functionality>   ->    <functionality>
 *
 */
__MBX_INLINE func_fips_approved mbx_is_fips_approved_func(enum FIPS_CRYPTO_MB_FUNC function)
{
    return ((int)function > 0);
}

#endif /* CRYPTO_MB_FIPS_CERT_H */
