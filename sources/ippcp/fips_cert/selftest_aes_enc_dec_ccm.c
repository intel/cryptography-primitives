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

#define IPPCP_IV_BYTE_LEN  (7) // initialization vector
#define IPPCP_AAD_BYTE_LEN (8) // additional authenticated data
#define IPPCP_MSG_BYTE_LEN (4)
#define IPPCP_TAG_BYTE_LEN (4)

/* KAT TEST */
/* secret key */
static const Ipp8u key[IPPCP_AES_KEY128_BYTE_LEN] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
                                                      0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
                                                      0x4c, 0x4d, 0x4e, 0x4f };
/* initialization vector */
static const Ipp8u iv[IPPCP_IV_BYTE_LEN] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
/* plaintext */
static const Ipp8u ptext[IPPCP_MSG_BYTE_LEN] = { 0x20, 0x21, 0x22, 0x23 };
/* ciphertext */
static const Ipp8u ctext[IPPCP_MSG_BYTE_LEN] = { 0x71, 0x62, 0x01, 0x5b };
/* tag */
static const Ipp8u tag[IPPCP_TAG_BYTE_LEN] = { 0x4d, 0xac, 0x25, 0x5d };
/* additional authenticated data */
static const Ipp8u ad[IPPCP_AAD_BYTE_LEN] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

IPPFUN(fips_test_status, fips_selftest_ippsAESEncryptDecryptCCM_get_size, (int* pBuffSize))
{
    /* return bad status if input pointer is NULL */
    IPP_BADARG_RET((NULL == pBuffSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int ctx_size  = 0;
    sts           = ippsAES_CCMGetSize(&ctx_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    ctx_size += IPPCP_AES_ALIGNMENT;
    *pBuffSize = ctx_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsAES_CCMEncrypt, (Ipp8u * pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */
    int internalMemMgm = 0;
    int ctx_size       = 0;
    sts                = fips_selftest_ippsAESEncryptDecryptCCM_get_size(&ctx_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* output ciphertext */
    Ipp8u out_ctext[IPPCP_MSG_BYTE_LEN];
    /* output tag */
    Ipp8u out_tag[IPPCP_TAG_BYTE_LEN];
    /* context */
    IppsAES_CCMState* state = (IppsAES_CCMState*)(IPP_ALIGNED_PTR(pBuffer, IPPCP_AES_ALIGNMENT));

    /* context initialization */
    sts = ippsAES_CCMGetSize(&ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_CCMInit(key, IPPCP_AES_KEY128_BYTE_LEN, state, ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* encryption setup */
    sts = ippsAES_CCMMessageLen(IPPCP_MSG_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_CCMTagLen(IPPCP_TAG_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_CCMStart(iv, IPPCP_IV_BYTE_LEN, ad, IPPCP_AAD_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* encryption */
    for (int i = 0; i < IPPCP_MSG_BYTE_LEN; ++i) {
        sts = ippsAES_CCMEncrypt(ptext + i, out_ctext + i, 1, state);
        if (sts != ippStsNoErr) {
            MEMORY_FREE(pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
    }

    /* get tag */
    sts = ippsAES_CCMGetTag(out_tag, IPPCP_TAG_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* compare output to known answer */
    if (!ippcp_is_mem_eq(out_tag, IPPCP_TAG_BYTE_LEN, tag, IPPCP_TAG_BYTE_LEN)) { // tag
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }
    if (!ippcp_is_mem_eq(out_ctext, IPPCP_MSG_BYTE_LEN, ctext, IPPCP_MSG_BYTE_LEN)) { // ctext
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsAES_CCMDecrypt, (Ipp8u * pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */
    int internalMemMgm = 0;
    int ctx_size       = 0;
    sts                = fips_selftest_ippsAESEncryptDecryptCCM_get_size(&ctx_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* output plaintext */
    Ipp8u out_ptext[IPPCP_MSG_BYTE_LEN];
    /* output tag */
    Ipp8u out_tag[IPPCP_TAG_BYTE_LEN];
    /* context */
    IppsAES_CCMState* state = (IppsAES_CCMState*)(IPP_ALIGNED_PTR(pBuffer, IPPCP_AES_ALIGNMENT));

    /* context initialization */
    sts = ippsAES_CCMGetSize(&ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_CCMInit(key, IPPCP_AES_KEY128_BYTE_LEN, state, ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* decryption setup */
    sts = ippsAES_CCMMessageLen(IPPCP_MSG_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_CCMTagLen(IPPCP_TAG_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_CCMStart(iv, IPPCP_IV_BYTE_LEN, ad, IPPCP_AAD_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* decryption */
    for (int i = 0; i < IPPCP_MSG_BYTE_LEN; ++i) {
        sts = ippsAES_CCMDecrypt(ctext + i, out_ptext + i, 1, state);
        if (sts != ippStsNoErr) {
            MEMORY_FREE(pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
    }

    /* get tag */
    sts = ippsAES_CCMGetTag(out_tag, IPPCP_TAG_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* compare output to known answer */
    if (!ippcp_is_mem_eq(out_tag, IPPCP_TAG_BYTE_LEN, tag, IPPCP_TAG_BYTE_LEN)) { // tag
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }
    if (!ippcp_is_mem_eq(out_ptext, IPPCP_MSG_BYTE_LEN, ptext, IPPCP_MSG_BYTE_LEN)) { // ptext
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
