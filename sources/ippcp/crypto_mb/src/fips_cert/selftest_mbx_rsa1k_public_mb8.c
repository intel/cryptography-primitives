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

#if defined(_MSC_VER) && !defined(__INTEL_COMPILER)
#pragma warning(disable : 4206) // empty translation unit in MSVC
#endif

/* Selftests are disabled for now, since rsa 1k scheme is not FIPS-approved */
#if 0

#ifdef MBX_FIPS_MODE

#include <crypto_mb/fips_cert.h>
#include <internal/fips_cert/common.h>
#include <internal/rsa/ifma_rsa_method.h>

#include <crypto_mb/rsa.h>

/* KAT TEST (generated via internal tests) */
/* moduli */
static const int8u moduli[MBX_RSA1K_DATA_BYTE_LEN] = {
  0xf1,0x56,0x41,0xee,0x2e,0x6e,0x39,0x07,0x26,0x03,0x6a,0x49,0xcf,0x13,0x38,0xef,
  0xd7,0x57,0xed,0x82,0xa7,0x9a,0xd5,0x85,0xc5,0xc0,0x16,0x86,0x05,0x84,0xa3,0xa4,
  0x6b,0x3d,0x7f,0xa7,0xe1,0x6a,0x92,0x26,0x1c,0xb4,0x30,0x4b,0xaa,0xfb,0xf2,0x17,
  0xcd,0x43,0x2e,0x4c,0x52,0x1a,0x7c,0xa3,0x43,0x46,0x0f,0xd1,0xa8,0x7f,0x18,0x2a,
  0x34,0x19,0x0f,0x7f,0xc5,0xd5,0x6f,0x3a,0x23,0xb9,0xac,0xf0,0xb7,0x14,0x89,0x35,
  0xe8,0xa3,0xd6,0x50,0x81,0x58,0xd4,0xe4,0xd9,0x64,0xbb,0xea,0x8c,0xd4,0x5d,0xe0,
  0x2a,0x36,0xad,0x83,0xe1,0x92,0xa9,0xe3,0xf2,0xcb,0x56,0xc8,0x36,0xad,0x28,0x2e,
  0x8f,0x04,0xaa,0x26,0xc6,0x62,0x78,0x62,0xe5,0xab,0x93,0x8a,0x80,0xd6,0xc5,0xc3};
/* plaintext */
static const int8u plaintext[MBX_RSA1K_DATA_BYTE_LEN]  = {
  0x27,0x7e,0x53,0x66,0x1e,0x56,0x7a,0x12,0xdf,0xef,0x04,0x8e,0x7d,0x2d,0xf6,0x4a,
  0x68,0x1b,0xcd,0x5a,0x1c,0x79,0xbd,0x7f,0xdc,0x77,0xc6,0x7b,0xea,0xbe,0x26,0x8f,
  0x8e,0x4d,0x7b,0xc5,0x07,0xcc,0xe1,0x7b,0x4b,0x1e,0xc2,0x45,0xfd,0x8b,0xf5,0x56,
  0x16,0x45,0xa2,0x76,0x29,0xaf,0xe8,0x2d,0x1a,0x0f,0x69,0x1b,0x4f,0xe6,0xa9,0x5c,
  0xd6,0x27,0xd1,0xbe,0x49,0xe1,0x87,0x75,0x13,0xe4,0xf4,0x2c,0xde,0xa4,0x03,0x5b,
  0x9b,0xe9,0x11,0x29,0x7f,0x82,0xd7,0x74,0x2a,0xda,0xe3,0x7a,0xcb,0x23,0xab,0x1a,
  0x78,0xc2,0x9d,0xef,0x2f,0xd5,0x95,0xcf,0x81,0x8e,0x89,0x38,0x2f,0x46,0x16,0xb1,
  0x0e,0xab,0x91,0x75,0x2a,0x3c,0xbd,0xc8,0x00,0x61,0xc7,0x84,0x69,0xb6,0x5d,0xe2};
/* ciphertext */
static const int8u ciphertext[MBX_RSA1K_DATA_BYTE_LEN] = {
  0x18,0x4d,0x50,0xc3,0xb8,0xa4,0xa8,0xc7,0x76,0x5e,0x4b,0x47,0xe0,0x50,0xe9,0xa6,
  0xc5,0xe6,0x11,0xdf,0xf7,0x33,0x61,0x3c,0x89,0x70,0xc5,0xf9,0x8a,0x38,0x08,0xe6,
  0x03,0x24,0xf1,0x1a,0xe1,0x7d,0x66,0xf6,0xc9,0xc8,0xd2,0x7c,0x7e,0x97,0xc4,0x3a,
  0x62,0xa3,0x60,0x11,0xff,0x5c,0x80,0x27,0xba,0xc5,0x25,0x37,0xa7,0x75,0xb5,0x50,
  0xb3,0xa6,0x61,0xd3,0x16,0xa4,0x9d,0x64,0x4f,0x9e,0xdb,0x43,0x5c,0xea,0xb4,0xfb,
  0x68,0xa2,0xe7,0xb5,0x70,0x3d,0xc4,0xbe,0x1d,0xf4,0x9b,0xcb,0x3b,0xdc,0xa5,0xdb,
  0xc2,0x7d,0xe4,0x44,0x65,0x92,0x88,0x32,0xd7,0x3f,0x87,0xd7,0x1e,0x71,0xb1,0x41,
  0xe5,0xc1,0x8b,0xa1,0xd5,0x28,0x09,0x94,0x06,0x53,0x2c,0x4c,0x99,0x28,0x6d,0x8d};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_rsa1k_public_mb8(void) {
  fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

  /* output ciphertext */
  int8u out_ciphertext[MBX_LANES][MBX_RSA1K_DATA_BYTE_LEN];
  /* key operation */
  const mbx_RSA_Method* method = mbx_RSA1K_pub65537_Method();

  /* function input parameters */
  // plaintext
  const int8u *pa_plaintext[MBX_LANES] = {
    plaintext, plaintext, plaintext, plaintext,
    plaintext, plaintext, plaintext, plaintext};
  // ciphertext
  int8u *pa_ciphertext[MBX_LANES] = {
    out_ciphertext[0], out_ciphertext[1], out_ciphertext[2], out_ciphertext[3],
    out_ciphertext[4], out_ciphertext[5], out_ciphertext[6], out_ciphertext[7]};
  // moduli
  const int64u *pa_moduli[MBX_LANES] = {
    (int64u *)moduli, (int64u *)moduli, (int64u *)moduli, (int64u *)moduli,
    (int64u *)moduli, (int64u *)moduli, (int64u *)moduli, (int64u *)moduli};

  /* test function */
  mbx_status expected_status_mb8 = MBX_SET_STS_ALL(MBX_STATUS_OK);

  mbx_status sts;
  sts = mbx_rsa_public_mb8(pa_plaintext, pa_ciphertext, pa_moduli, MBX_RSA1K_DATA_BIT_LEN, method, NULL);
  if (expected_status_mb8 != sts) {
    test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
  }
  // compare output ciphertext to known answer
  int output_status;
  for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
    output_status = mbx_is_mem_eq(pa_ciphertext[i], MBX_RSA1K_DATA_BYTE_LEN, ciphertext, MBX_RSA1K_DATA_BYTE_LEN);
    if (!output_status) { // wrong output
      test_result = MBX_ALGO_SELFTEST_KAT_ERR;
    }
  }

  return test_result;
}

#ifndef BN_OPENSSL_DISABLE
/* exponent (for ssl function only) */
static const int8u exponent[MBX_RSA_PUB_EXP_BYTE_LEN] = {0x01,0x00,0x01};

// memory free macro
#define MEM_FREE(BN_PTR1, BN_PTR2) \
    {                              \
        BN_free(BN_PTR1);          \
        BN_free(BN_PTR2);          \
    }

DLL_PUBLIC
fips_test_status fips_selftest_mbx_rsa1k_public_ssl_mb8(void) {

  fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

  /* output ciphertext */
  int8u out_ciphertext[MBX_LANES][MBX_RSA1K_DATA_BYTE_LEN];
  /* ssl exponent */
  BIGNUM* BN_e = BN_new();
  /* ssl moduli */
  BIGNUM* BN_moduli = BN_new();
  /* check if allocated memory is valid */
  if(NULL == BN_e || NULL == BN_moduli) {
    test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
    MEM_FREE(BN_e, BN_moduli)
    return test_result;
  }
  /* function status and expected status */
  mbx_status sts;
  mbx_status expected_status_mb8 = MBX_SET_STS_ALL(MBX_STATUS_OK);
  /* output validity status */
  int output_status;

  /* set ssl parameters */
  BN_lebin2bn(exponent, MBX_RSA_PUB_EXP_BYTE_LEN, BN_e);
  BN_lebin2bn(moduli, MBX_RSA1K_DATA_BYTE_LEN, BN_moduli);

  /* function input parameters */
  // plaintext
  const int8u *pa_plaintext[MBX_LANES] = {
    plaintext, plaintext, plaintext, plaintext,
    plaintext, plaintext, plaintext, plaintext};
  // ciphertext
  int8u *pa_ciphertext[MBX_LANES] = {
    out_ciphertext[0], out_ciphertext[1], out_ciphertext[2], out_ciphertext[3],
    out_ciphertext[4], out_ciphertext[5], out_ciphertext[6], out_ciphertext[7]};
  // moduli
  const BIGNUM *pa_moduli[MBX_LANES] = {
    (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli,
    (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli};
  // exponent
  const BIGNUM *pa_e[MBX_LANES] = {
    (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e,
    (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e};

  /* test function */
  sts = mbx_rsa_public_ssl_mb8(pa_plaintext, pa_ciphertext, pa_e, pa_moduli, MBX_RSA1K_DATA_BIT_LEN);
  if (expected_status_mb8 != sts) {
    test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
  }
  // compare output signature to known answer
  for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
    output_status = mbx_is_mem_eq(pa_ciphertext[i], MBX_RSA1K_DATA_BYTE_LEN, ciphertext, MBX_RSA1K_DATA_BYTE_LEN);
    if (!output_status) { // wrong output
      test_result = MBX_ALGO_SELFTEST_KAT_ERR;
    }
  }

  // memory free
  MEM_FREE(BN_e, BN_moduli)

  return test_result;
}

#endif // BN_OPENSSL_DISABLE
#endif // MBX_FIPS_MODE
#endif // #if 0
