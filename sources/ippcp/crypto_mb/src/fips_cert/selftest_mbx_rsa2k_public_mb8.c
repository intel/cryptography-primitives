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
#include <internal/rsa/ifma_rsa_method.h>

#include <crypto_mb/rsa.h>

/* KAT TEST (generated via internal tests) */
/* moduli */
static const int8u moduli[MBX_RSA2K_DATA_BYTE_LEN] = {
  0x17,0xdd,0x3c,0x74,0x0f,0x12,0x7f,0x99,0xd8,0x9e,0xd3,0xe7,0x60,0x16,0x15,0x7e,
  0xe4,0x7c,0xa9,0x58,0x26,0x9b,0x98,0x6e,0x4e,0x9f,0x17,0x1a,0xfa,0x46,0x03,0x3a,
  0xf0,0xdf,0xcc,0xc9,0x39,0x16,0x5e,0x02,0xbd,0x4c,0x73,0x5d,0xa2,0x56,0x8d,0x9c,
  0x1a,0xb1,0x2c,0xca,0x7e,0xbd,0x9b,0xad,0xa7,0x8e,0xe0,0xae,0xb3,0xb8,0x8a,0x93,
  0x91,0x85,0x83,0x9a,0x76,0x08,0xa6,0x4e,0xf7,0xde,0xff,0xe3,0x09,0xed,0x60,0x98,
  0x17,0x8f,0xaf,0x6a,0x58,0x81,0x12,0x0d,0xfb,0xff,0x56,0xc7,0x3f,0xa0,0x72,0x93,
  0x0c,0x96,0xfa,0xa7,0xfc,0x16,0x95,0xfd,0x85,0x7a,0xaa,0xab,0x9c,0xf9,0x60,0x91,
  0x1b,0xf0,0xb1,0xdf,0x28,0x39,0xf3,0xb9,0x7b,0x56,0x87,0x66,0x73,0xe6,0x90,0xc9,
  0x54,0x87,0x5d,0xab,0x41,0x2a,0x31,0x91,0x5c,0x87,0x7c,0x5c,0x55,0xb2,0x65,0x77,
  0x5d,0x94,0x6a,0x2f,0x72,0xec,0xc8,0x9e,0x60,0x9f,0x32,0x49,0x24,0x99,0x81,0x41,
  0xfa,0x8c,0x04,0x2d,0x6c,0xeb,0x43,0x1b,0x0f,0xbe,0x85,0xbb,0xb5,0x53,0x5c,0xa6,
  0x86,0x6a,0x78,0x54,0x2e,0x82,0x34,0xdf,0x7f,0x57,0x0b,0x27,0x87,0x83,0x5e,0xfb,
  0x0d,0x4f,0xa2,0x5d,0xfa,0x89,0x74,0x75,0xad,0x9f,0x26,0x3f,0x12,0x38,0xc5,0xc3,
  0x91,0xf0,0x8a,0xe7,0xde,0x10,0xce,0xf3,0xf8,0x89,0x1a,0xf0,0xee,0x3c,0xa2,0x2c,
  0x98,0xbd,0xf7,0x03,0xe1,0x46,0xc1,0x4d,0xdf,0xbb,0xae,0x6a,0x61,0xf7,0xc8,0x56,
  0x31,0xd5,0xf5,0xbb,0x08,0x8d,0xfd,0x51,0x28,0x3c,0x82,0xe0,0x0d,0x7d,0xc1,0xf0};
/* plaintext */
static const int8u plaintext[MBX_RSA2K_DATA_BYTE_LEN] = {
  0x5c,0x14,0x01,0xf4,0x3f,0x46,0x71,0xd5,0x3e,0xc3,0xe1,0x9a,0xec,0xb7,0x44,0x97,
  0x73,0x59,0x1e,0x00,0xa5,0x5d,0xe7,0x9a,0xf4,0x0a,0xac,0x21,0x7c,0x70,0x5a,0x54,
  0x23,0x61,0xaa,0x4c,0x02,0x4f,0x80,0xed,0x30,0x2c,0x4f,0xe9,0x8b,0x92,0x53,0x93,
  0xa3,0xdc,0xe7,0x66,0xc4,0x90,0xa1,0x2b,0x60,0xea,0x5e,0x5f,0x58,0x63,0x47,0x75,
  0x2c,0xd1,0x2b,0x6c,0x06,0x3e,0x52,0x4f,0x7c,0x54,0x90,0x9c,0xbc,0xf5,0x73,0xa2,
  0xcb,0xb3,0x3c,0x24,0xb3,0x0a,0xfd,0xa7,0x30,0xeb,0x3c,0x29,0x1c,0x51,0x38,0x9c,
  0x6f,0xf6,0xa6,0xc9,0xb7,0xf3,0x75,0xb0,0x30,0x74,0x5b,0x3c,0x44,0x23,0x10,0xa0,
  0xbd,0x65,0xf9,0x11,0x09,0xf3,0x9f,0x63,0x03,0xf3,0x56,0xa8,0x76,0xce,0xac,0x70,
  0x9c,0x21,0x55,0x62,0xb9,0xc6,0x91,0xe8,0xb6,0x82,0x4d,0x4f,0x08,0xe7,0xa5,0x72,
  0x50,0xce,0x8d,0x94,0x7d,0xdc,0xe3,0x20,0x05,0x0d,0x53,0xe4,0x74,0xf7,0x85,0xb8,
  0x98,0x09,0xa6,0xa0,0xc3,0xd5,0xe9,0x8c,0x23,0x17,0xd5,0x26,0x72,0x15,0x1e,0xf7,
  0x28,0xa1,0x2b,0x24,0x1d,0xbe,0x45,0x38,0xe2,0xd1,0xf6,0xb1,0x0f,0x58,0xf7,0x67,
  0x2b,0x2c,0x39,0x81,0x5c,0x89,0xf2,0x9d,0x07,0x21,0xd3,0xde,0x48,0x8a,0x3a,0xca,
  0x15,0x0c,0x21,0x32,0xd4,0x04,0x88,0x23,0xb4,0x66,0x3f,0xe8,0x24,0xae,0x4b,0x57,
  0x7b,0x32,0x87,0x47,0x0d,0x2a,0x63,0x5d,0x6d,0xa2,0x38,0xc6,0x2b,0xbe,0x65,0xf2,
  0x27,0xdd,0xe6,0x0b,0x4b,0xdd,0x39,0xa6,0x5a,0x38,0x96,0x3e,0x81,0x57,0xcf,0xf1};
/* ciphertext */
static const int8u ciphertext[MBX_RSA2K_DATA_BYTE_LEN] = {
  0x71,0x4b,0x43,0x7d,0x01,0x36,0xab,0x29,0xcd,0x95,0xa6,0x7c,0x30,0x70,0x51,0xd4,
  0xc1,0x06,0x94,0x9f,0xff,0x50,0x84,0x87,0x84,0x91,0x39,0x65,0x40,0x2c,0x30,0x6f,
  0x02,0x7c,0x0e,0xc7,0xf0,0x7d,0x1c,0xb4,0xe3,0xef,0x01,0xb0,0xde,0x3c,0xb3,0x5a,
  0xce,0xbb,0xe0,0xf8,0xcd,0x3a,0x03,0xff,0x96,0x16,0xe6,0x79,0x32,0x0d,0x23,0xcb,
  0xd2,0xe1,0x55,0xcc,0xa2,0x49,0x2a,0x52,0x64,0x5f,0xe6,0x1f,0xcc,0xe8,0x7b,0x7d,
  0xd3,0x14,0x4e,0x6d,0x74,0x0f,0x94,0x3d,0x77,0x91,0x65,0x54,0xa6,0x24,0x60,0x1f,
  0x33,0xda,0xa7,0xc7,0xf0,0x29,0xb3,0xb5,0x07,0xb0,0xed,0x5c,0x27,0x65,0x5f,0x6f,
  0x0a,0x8f,0x12,0x0c,0x25,0x41,0xce,0x9e,0x16,0x7b,0x2e,0x03,0x9b,0x59,0xe0,0x72,
  0x7d,0xe2,0x1a,0x82,0x57,0x2f,0x75,0x6c,0x68,0xd8,0xf8,0x3b,0x87,0xcf,0x32,0x04,
  0xe0,0xfc,0x23,0x35,0x71,0xb0,0x32,0x17,0xe4,0xfd,0x7b,0x6a,0xd0,0x6c,0x35,0xdf,
  0x3e,0x93,0x59,0xc1,0x42,0x71,0x7c,0x11,0x3c,0xb2,0xe6,0x6f,0xdc,0xfe,0xd5,0x79,
  0x3e,0x47,0x89,0xf4,0x08,0x0b,0x6c,0x58,0xdc,0x0a,0x1f,0x72,0x3f,0x92,0x55,0x17,
  0x27,0xde,0xa3,0xa2,0x1f,0xe4,0xd5,0xfa,0x8f,0xf1,0x8c,0xe3,0x28,0x7c,0xcd,0xa2,
  0xe7,0xbf,0x95,0xd9,0xf1,0xf7,0x83,0xf1,0x94,0x7d,0xbc,0x14,0xf1,0x2b,0x94,0xd6,
  0x84,0x03,0x84,0x99,0x97,0x02,0x7e,0x90,0x3d,0x5e,0x05,0x43,0xfd,0x12,0x0d,0x75,
  0x8e,0xec,0x56,0x6d,0xde,0x8c,0x10,0x9c,0xd9,0xbe,0xa5,0x15,0xa6,0x1f,0x3a,0xf6};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_rsa2k_public_mb8(void) {
  fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

  /* output ciphertext */
  int8u out_ciphertext[MBX_LANES][MBX_RSA2K_DATA_BYTE_LEN];
  /* key operation */
  const mbx_RSA_Method* method = mbx_RSA2K_pub65537_Method();
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
  mbx_status sts;
  sts = mbx_rsa_public_mb8(pa_plaintext, pa_ciphertext, pa_moduli, MBX_RSA2K_DATA_BIT_LEN, method, NULL);
  test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

  // compare output ciphertext to known answer
  int output_status;
  for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
    output_status = mbx_is_mem_eq(pa_ciphertext[i], MBX_RSA2K_DATA_BYTE_LEN, ciphertext, MBX_RSA2K_DATA_BYTE_LEN);
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
#define MEM_FREE(BN_PTR1, BN_PTR2) { \
  BN_free(BN_PTR1);                  \
  BN_free(BN_PTR2); }

DLL_PUBLIC
fips_test_status fips_selftest_mbx_rsa2k_public_ssl_mb8(void) {

  fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

  /* output ciphertext */
  int8u out_ciphertext[MBX_LANES][MBX_RSA2K_DATA_BYTE_LEN];
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

  /* set ssl parameters */
  BN_lebin2bn(exponent, MBX_RSA_PUB_EXP_BYTE_LEN, BN_e);
  BN_lebin2bn(moduli, MBX_RSA2K_DATA_BYTE_LEN, BN_moduli);

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
  const BIGNUM *pa_e[MBX_LANES] = {
    (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e,
    (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e};

  /* test function */
  mbx_status sts;
  sts = mbx_rsa_public_ssl_mb8(pa_plaintext, pa_ciphertext, pa_e, pa_moduli, MBX_RSA2K_DATA_BIT_LEN);
  test_result = mbx_selftest_check_if_success(sts, MBX_ALGO_SELFTEST_BAD_ARGS_ERR);

  // compare output signature to known answer
  int output_status;
  for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
    output_status = mbx_is_mem_eq(pa_ciphertext[i], MBX_RSA2K_DATA_BYTE_LEN, ciphertext, MBX_RSA2K_DATA_BYTE_LEN);
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
