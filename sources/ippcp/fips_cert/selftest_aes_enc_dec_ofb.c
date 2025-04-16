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
#ifdef _IPP_DATA

#include "ippcp/fips_cert.h"
#include "fips_cert_internal/common.h"

#define OFB_BLOCK_LEN (16)

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
    0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
    0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03, 0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e, 0xd8, 0x25,
    0x97, 0x40, 0x05, 0x1e, 0x9c, 0x5f, 0xec, 0xf6, 0x43, 0x44, 0xf7, 0xa8, 0x22, 0x60, 0xed, 0xcc,
    0x30, 0x4c, 0x65, 0x28, 0xf6, 0x59, 0xc7, 0x78, 0x66, 0xa5, 0x10, 0xd9, 0xc1, 0xd6, 0xae, 0x5e
};
/* initialization vector after enc|dec */
static const Ipp8u out_iv[IPPCP_IV128_BYTE_LEN] = {
    0xc6, 0xd3, 0x41, 0x6d, 0x29, 0x16, 0x5c, 0x6f, 0xcb, 0x8e, 0x51, 0xa2, 0x27, 0xba, 0x99, 0x4e
};

IPPFUN(fips_test_status, fips_selftest_ippsAESEncryptOFB, (Ipp8u * pBuffer))
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

    /* initialization vector */
    Ipp8u iv[IPPCP_IV128_BYTE_LEN] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    /* output ciphertext */
    Ipp8u out_ctext[IPPCP_AES_MSG_BYTE_LEN];
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
    sts = ippsAESEncryptOFB(ptext, out_ctext, IPPCP_AES_MSG_BYTE_LEN, OFB_BLOCK_LEN, spec, iv);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* compare output to known answer */
    if (!ippcp_is_mem_eq(
            out_ctext, IPPCP_AES_MSG_BYTE_LEN, ctext, IPPCP_AES_MSG_BYTE_LEN) || // ciphertext
        !ippcp_is_mem_eq(
            out_iv, IPPCP_IV128_BYTE_LEN, iv, IPPCP_IV128_BYTE_LEN)) { // initialization vector
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsAESDecryptOFB, (Ipp8u * pBuffer))
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

    /* output plaintext */
    Ipp8u out_ptext[IPPCP_AES_MSG_BYTE_LEN];
    /* initialization vector */
    Ipp8u iv[IPPCP_IV128_BYTE_LEN] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
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
    sts = ippsAESDecryptOFB(ctext, out_ptext, IPPCP_AES_MSG_BYTE_LEN, OFB_BLOCK_LEN, spec, iv);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* compare output to known answer */
    if (!ippcp_is_mem_eq(
            out_ptext, IPPCP_AES_MSG_BYTE_LEN, ptext, IPPCP_AES_MSG_BYTE_LEN) || // plaintext
        !ippcp_is_mem_eq(
            out_iv, IPPCP_IV128_BYTE_LEN, iv, IPPCP_IV128_BYTE_LEN)) { // initialization vector
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
