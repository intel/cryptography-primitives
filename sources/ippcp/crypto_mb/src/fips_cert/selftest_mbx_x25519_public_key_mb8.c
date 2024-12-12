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

/* Selftests are disabled for now, since x25519 scheme is not FIPS-approved yet */
#if 0
#ifdef MBX_FIPS_MODE

#include <crypto_mb/fips_cert.h>
#include <internal/fips_cert/common.h>

#include <crypto_mb/x25519.h>

/* KAT TEST (taken from internal tests) */
/* private key */
static const int8u prv_key[MBX_X25519_DATA_BYTE_LEN]  = {
  0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
  0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a};
/* public key */
static const int8u pub_key[MBX_X25519_DATA_BYTE_LEN] = {
  0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
  0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_x25519_public_key_mb8(void) {
  fips_test_status test_result = MBX_ALGO_SELFTEST_OK;
  /* output public key */
  int8u out_pub_key[MBX_LANES][MBX_X25519_DATA_BYTE_LEN];
  /* function input parameters */
  // output public key
  int8u *const pa_pub_key[MBX_LANES] = {
    out_pub_key[0], out_pub_key[1], out_pub_key[2], out_pub_key[3],
    out_pub_key[4], out_pub_key[5], out_pub_key[6], out_pub_key[7]};
  // private key
  const int8u *const pa_prv_key[MBX_LANES] = {
    prv_key, prv_key, prv_key, prv_key,
    prv_key, prv_key, prv_key, prv_key};
  /* test function */
  mbx_status expected_status_mb8 = MBX_SET_STS_ALL(MBX_STATUS_OK);
  mbx_status sts;
  sts = mbx_x25519_public_key_mb8(pa_pub_key, pa_prv_key);
  if (sts != expected_status_mb8){
    test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
  }
  // compare output to known answer
  for (int i = 0; (i < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++i) {
    if(!mbx_is_mem_eq(pub_key, MBX_X25519_DATA_BYTE_LEN, pa_pub_key[i], MBX_X25519_DATA_BYTE_LEN)) {
      test_result = MBX_ALGO_SELFTEST_KAT_ERR;
    }
  }
  return test_result;
}

#endif // MBX_FIPS_MODE
#endif
