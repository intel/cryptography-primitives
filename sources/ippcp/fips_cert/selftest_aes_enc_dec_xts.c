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

/* Selftests are disabled for now, since AES-XTS algorithm didn't pass CAVP testing */
#if 0
#ifdef IPPCP_FIPS_MODE
#include "ippcp.h"
#include "owndefs.h"
#include "dispatcher.h"

// FIPS selftests are not processed by dispatcher.
// Prevent several copies of the same functions.
#ifdef _IPP_DATA

#include "ippcp/fips_cert.h"
#include "fips_cert_internal/common.h"

#define IPPCP_AES_KEY256_BIT_LEN     (256)
#define IPPCP_DATA_UNIT_BIT_LEN      (128)
#define IPPCP_TWEAK_BYTE_LEN         (16)
#define IPPCP_MSG_BYTE_LEN           (16)
#define IPPCP_START_CIPHER_BLOCK_NUM (0)

/* KAT TEST */
/* tweak vector */
static const Ipp8u tweak[IPPCP_TWEAK_BYTE_LEN] = {
  0x4f,0xae,0xf7,0x11,0x7c,0xda,0x59,0xc6,
  0x6e,0x4b,0x92,0x01,0x3e,0x76,0x8a,0xd5};
/* secret key */
static const Ipp8u key[IPPCP_AES_KEY256_BYTE_LEN] = {
  0xa1,0xb9,0x0c,0xba,0x3f,0x06,0xac,0x35,0x3b,0x2c,0x34,0x38,0x76,0x08,0x17,0x62,
  0x09,0x09,0x23,0x02,0x6e,0x91,0x77,0x18,0x15,0xf2,0x9d,0xab,0x01,0x93,0x2f,0x2f};
/* plaintext */
static const Ipp8u ptext[IPPCP_MSG_BYTE_LEN] = {
  0xeb,0xab,0xce,0x95,0xb1,0x4d,0x3c,0x8d,
  0x6f,0xb3,0x50,0x39,0x07,0x90,0x31,0x1c};
/* ciphertext */
static const Ipp8u ctext[IPPCP_MSG_BYTE_LEN] = {
  0x77,0x8a,0xe8,0xb4,0x3c,0xb9,0x8d,0x5a,
  0x82,0x50,0x81,0xd5,0xbe,0x47,0x1c,0x63};

IPPFUN(fips_test_status, fips_selftest_ippsAESEncryptDecryptXTS_get_size, (int* pBuffSize)) {
    /* return bad status if input pointer is NULL */
    IPP_BADARG_RET((NULL == pBuffSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
    
    IppStatus sts = ippStsNoErr;
    int ctx_size = 0;
    sts = ippsAES_XTSGetSize(&ctx_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    
    ctx_size += IPPCP_AES_ALIGNMENT;
    *pBuffSize = ctx_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsAES_XTSEncrypt, (Ipp8u *pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */ 
    int internalMemMgm = 0;
    int ctx_size = 0;
    fips_selftest_ippsAESEncryptDecryptXTS_get_size(&ctx_size);
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* output ciphertext */
    Ipp8u out_ctext[IPPCP_MSG_BYTE_LEN];
    /* context */
    IppsAES_XTSSpec* spec = (IppsAES_XTSSpec*)(IPP_ALIGNED_PTR(pBuffer, IPPCP_AES_ALIGNMENT));

    /* context initialization */
    ippsAES_XTSGetSize(&ctx_size);
    sts = ippsAES_XTSInit(key, IPPCP_AES_KEY256_BIT_LEN, IPPCP_DATA_UNIT_BIT_LEN, spec, ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* function call */
    sts = ippsAES_XTSEncrypt(ptext, out_ctext, IPPCP_DATA_UNIT_BIT_LEN, spec, tweak, IPPCP_START_CIPHER_BLOCK_NUM);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* compare output to known answer */
    if (!ippcp_is_mem_eq(out_ctext, IPPCP_MSG_BYTE_LEN, ctext, IPPCP_MSG_BYTE_LEN)){
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsAES_XTSDecrypt, (Ipp8u *pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */ 
    int internalMemMgm = 0;
    int ctx_size = 0;
    fips_selftest_ippsAESEncryptDecryptXTS_get_size(&ctx_size);
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* output plaintext */
    Ipp8u out_ptext[IPPCP_MSG_BYTE_LEN];
    /* context */
    IppsAES_XTSSpec* spec = (IppsAES_XTSSpec*)(IPP_ALIGNED_PTR(pBuffer, IPPCP_AES_ALIGNMENT));

    /* context initialization */
    ippsAES_XTSGetSize(&ctx_size);
    sts = ippsAES_XTSInit(key, IPPCP_AES_KEY256_BIT_LEN, IPPCP_DATA_UNIT_BIT_LEN, spec, ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* function call */
    sts = ippsAES_XTSDecrypt(ctext, out_ptext, IPPCP_DATA_UNIT_BIT_LEN, spec, tweak, IPPCP_START_CIPHER_BLOCK_NUM);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* compare output to known answer */
    if (!ippcp_is_mem_eq(out_ptext, IPPCP_MSG_BYTE_LEN, ptext, IPPCP_MSG_BYTE_LEN)){
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
#endif
