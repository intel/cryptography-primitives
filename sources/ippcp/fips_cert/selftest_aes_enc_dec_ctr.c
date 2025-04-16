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

#ifdef IPPCP_FIPS_MODE
#include "ippcp.h"
#include "owndefs.h"
#include "dispatcher.h"

// FIPS selftests are not processed by dispatcher.
// Prevent several copies of the same functions.
#if defined(_IPP_DATA)

#include "ippcp/fips_cert.h"
#include "fips_cert_internal/common.h"

#define IPPCP_CTR_BYTE_LEN (16)
#define IPPCP_CTR_BIT_LEN  ((IPPCP_CTR_BYTE_LEN) * 8)

/* KAT TEST */
/* secret key */
static const Ipp8u key[IPPCP_AES_KEY128_BYTE_LEN] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                                      0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                                      0x09, 0xcf, 0x4f, 0x3c };
/* plaintext */
static const Ipp8u ptext[IPPCP_AES_MSG_BYTE_LEN] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
/* ciphertext */
static const Ipp8u ctext[IPPCP_AES_MSG_BYTE_LEN] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
    0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
    0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
};
/* counter after enc|dec */
static const Ipp8u out_ctr[IPPCP_CTR_BYTE_LEN] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                                   0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xff, 0x03 };

IPPFUN(fips_test_status, fips_selftest_ippsAESEncryptCTR, (Ipp8u * pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */
    int internalMemMgm = 0;
    int ctx_size       = 0;
    sts                = fips_selftest_ippsAESEncryptDecrypt_get_size(&ctx_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* counter */
    Ipp8u ctr[IPPCP_CTR_BYTE_LEN] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    /* output ciphertext */
    Ipp8u out_ctext[IPPCP_AES_MSG_BYTE_LEN];
    /* context */
    IppsAESSpec* spec = (IppsAESSpec*)(IPP_ALIGNED_PTR(pBuffer, IPPCP_AES_ALIGNMENT));

    /* context initialization */
    ippsAESGetSize(&ctx_size);
    sts = ippsAESInit(key, IPPCP_AES_KEY128_BYTE_LEN, spec, ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* function call */
    sts = ippsAESEncryptCTR(ptext, out_ctext, IPPCP_AES_MSG_BYTE_LEN, spec, ctr, IPPCP_CTR_BIT_LEN);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* compare output to known answer */
    if (!ippcp_is_mem_eq(
            out_ctext, IPPCP_AES_MSG_BYTE_LEN, ctext, IPPCP_AES_MSG_BYTE_LEN) ||  // ciphertext
        !ippcp_is_mem_eq(out_ctr, IPPCP_CTR_BYTE_LEN, ctr, IPPCP_CTR_BYTE_LEN)) { // counter
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsAESDecryptCTR, (Ipp8u * pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */
    int internalMemMgm = 0;
    int ctx_size       = 0;
    fips_selftest_ippsAESEncryptDecrypt_get_size(&ctx_size);
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* counter */
    Ipp8u ctr[IPPCP_CTR_BYTE_LEN] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    /* output plaintext */
    Ipp8u out_ptext[IPPCP_AES_MSG_BYTE_LEN];
    /* context */
    IppsAESSpec* spec = (IppsAESSpec*)(IPP_ALIGNED_PTR(pBuffer, IPPCP_AES_ALIGNMENT));

    /* context initialization */
    sts = ippsAESGetSize(&ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAESInit(key, IPPCP_AES_KEY128_BYTE_LEN, spec, ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* function call */
    sts = ippsAESDecryptCTR(ctext, out_ptext, IPPCP_AES_MSG_BYTE_LEN, spec, ctr, IPPCP_CTR_BIT_LEN);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* compare output to known answer */
    if (!ippcp_is_mem_eq(
            out_ptext, IPPCP_AES_MSG_BYTE_LEN, ptext, IPPCP_AES_MSG_BYTE_LEN) ||  // plaintext
        !ippcp_is_mem_eq(out_ctr, IPPCP_CTR_BYTE_LEN, ctr, IPPCP_CTR_BYTE_LEN)) { // counter
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
