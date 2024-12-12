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

/* KAT TEST (taken from wycheproof test) */
/* public key */
static const int8u pub_key[MBX_X25519_DATA_BYTE_LEN]       = {0x50,0x4a,0x36,0x99,0x9f,0x48,0x9c,0xd2,
                                                          0xfd,0xbc,0x08,0xba,0xff,0x3d,0x88,0xfa,
                                                          0x00,0x56,0x9b,0xa9,0x86,0xcb,0xa2,0x25,
                                                          0x48,0xff,0xde,0x80,0xf9,0x80,0x68,0x29};
/* private key */
static const int8u prv_key[MBX_X25519_DATA_BYTE_LEN]       = {0xc8,0xa9,0xd5,0xa9,0x10,0x91,0xad,0x85,
                                                          0x1c,0x66,0x8b,0x07,0x36,0xc1,0xc9,0xa0,
                                                          0x29,0x36,0xc0,0xd3,0xad,0x62,0x67,0x08,
                                                          0x58,0x08,0x80,0x47,0xba,0x05,0x74,0x75};
/* shared key */
static const int8u shared_key[MBX_X25519_DATA_BYTE_LEN]    = {0x43,0x6a,0x2c,0x04,0x0c,0xf4,0x5f,0xea,
                                                          0x9b,0x29,0xa0,0xcb,0x81,0xb1,0xf4,0x14,
                                                          0x58,0xf8,0x63,0xd0,0xd6,0x1b,0x45,0x3d,
                                                          0x0a,0x98,0x27,0x20,0xd6,0xd6,0x13,0x20};

DLL_PUBLIC
fips_test_status fips_selftest_mbx_x25519_mb8(void) {
  fips_test_status test_result = MBX_ALGO_SELFTEST_OK;

  /* output shared key */
  int8u out_shared_key[MBX_LANES][MBX_X25519_DATA_BYTE_LEN];

  /* function input parameters */
  // public key
  const int8u *const pa_pub_key[MBX_LANES] = {
      pub_key, pub_key, pub_key, pub_key,
      pub_key, pub_key, pub_key, pub_key};
  // private key
  const int8u *const pa_prv_key[MBX_LANES] = {
      prv_key, prv_key, prv_key, prv_key,
      prv_key, prv_key, prv_key, prv_key};
  // output shared key
  int8u *pa_shared_key[MBX_LANES] = {
    out_shared_key[0], out_shared_key[1], out_shared_key[2], out_shared_key[3],
    out_shared_key[4], out_shared_key[5], out_shared_key[6], out_shared_key[7]};

  /* test function */
  mbx_status expected_status_mb8 = MBX_SET_STS_ALL(MBX_STATUS_OK);

  mbx_status sts;
  sts = mbx_x25519_mb8(pa_shared_key, pa_prv_key, pa_pub_key);
  if (expected_status_mb8 != sts) {
    test_result = MBX_ALGO_SELFTEST_BAD_ARGS_ERR;
  }
  // compare computed shared key to known answer
  int output_status;
  for (int j = 0; (j < MBX_LANES) && (MBX_ALGO_SELFTEST_OK == test_result); ++j) {
    output_status = mbx_is_mem_eq(pa_shared_key[j], MBX_X25519_DATA_BYTE_LEN, shared_key, MBX_X25519_DATA_BYTE_LEN);
    if (!output_status) { // wrong output
      test_result = MBX_ALGO_SELFTEST_KAT_ERR;
    }
  }

  return test_result;
}

#endif // MBX_FIPS_MODE
#endif
