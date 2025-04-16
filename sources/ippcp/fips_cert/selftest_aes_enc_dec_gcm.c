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

#define IV_BYTE_LEN  (12) // initialization vector
#define AD_BYTE_LEN  (20) // additional authenticated data
#define MSG_BYTE_LEN (60)
#define TAG_BYTE_LEN (16)

/* KAT TEST */
/* secret key */
static const Ipp8u key[IPPCP_AES_KEY128_BYTE_LEN] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65,
                                                      0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
                                                      0x67, 0x30, 0x83, 0x08 };
/* initialization vector */
static const Ipp8u iv[IV_BYTE_LEN] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                                       0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
/* plaintext */
static const Ipp8u ptext[MSG_BYTE_LEN] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26,
    0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
    0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
    0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
};
/* ciphertext */
static const Ipp8u ctext[MSG_BYTE_LEN] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4,
    0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
    0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac,
    0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91
};
/* tag */
static const Ipp8u tag[TAG_BYTE_LEN] = { 0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
                                         0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47 };
/* additional authenticated data */
static const Ipp8u ad[AD_BYTE_LEN] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                                       0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2 };

IPPFUN(fips_test_status, fips_selftest_ippsAES_GCM_get_size, (int* pBufferSize))
{
    /* return bad status if input pointer is NULL */
    IPP_BADARG_RET((NULL == pBufferSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int ctx_size  = 0;
    sts           = ippsAES_GCMGetSize(&ctx_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    ctx_size += IPPCP_AES_ALIGNMENT;
    *pBufferSize = ctx_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsAES_GCMEncrypt, (Ipp8u * pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */
    int internalMemMgm = 0;
    int ctx_size       = 0;
    sts                = fips_selftest_ippsAES_GCM_get_size(&ctx_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* output ciphertext */
    Ipp8u out_ctext[MSG_BYTE_LEN];
    /* output tag */
    Ipp8u out_tag[TAG_BYTE_LEN];
    /* context */
    IppsAES_GCMState* state = (IppsAES_GCMState*)IPP_ALIGNED_PTR(pBuffer, IPPCP_AES_ALIGNMENT);

    /* context initialization */
    ippsAES_GCMGetSize(&ctx_size);
    sts = ippsAES_GCMInit(key, IPPCP_AES_KEY128_BYTE_LEN, state, ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* encryption setup */
    sts = ippsAES_GCMStart(iv, IV_BYTE_LEN, ad, AD_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* encryption */
    for (int i = 0; i < MSG_BYTE_LEN; ++i) {
        sts = ippsAES_GCMEncrypt(ptext + i, out_ctext + i, 1, state);
        if (sts != ippStsNoErr) {
            MEMORY_FREE(pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
    }
    /* get tag */
    sts = ippsAES_GCMGetTag(out_tag, TAG_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* compare output to known answer*/
    if (!ippcp_is_mem_eq(out_tag, TAG_BYTE_LEN, tag, TAG_BYTE_LEN)) { // tag
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }
    if (!ippcp_is_mem_eq(out_ctext, MSG_BYTE_LEN, ctext, MSG_BYTE_LEN)) { // ctext
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsAES_GCMDecrypt, (Ipp8u * pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */
    int internalMemMgm = 0;
    int ctx_size       = 0;
    sts                = fips_selftest_ippsAES_GCM_get_size(&ctx_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* output plaintext */
    Ipp8u out_ptext[MSG_BYTE_LEN];
    /* output tag */
    Ipp8u out_tag[TAG_BYTE_LEN];
    /* context */
    IppsAES_GCMState* state = (IppsAES_GCMState*)IPP_ALIGNED_PTR(pBuffer, IPPCP_AES_ALIGNMENT);

    /* context initialization */
    sts = ippsAES_GCMGetSize(&ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_GCMInit(key, IPPCP_AES_KEY128_BYTE_LEN, state, ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* decryption setup */
    sts = ippsAES_GCMStart(iv, IV_BYTE_LEN, ad, AD_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* decryption */
    for (int i = 0; i < MSG_BYTE_LEN; ++i) {
        sts = ippsAES_GCMDecrypt(ctext + i, out_ptext + i, 1, state);
        if (sts != ippStsNoErr) {
            MEMORY_FREE(pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
    }
    /* get tag */
    sts = ippsAES_GCMGetTag(out_tag, TAG_BYTE_LEN, state);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* compare output to known answer */
    if (!ippcp_is_mem_eq(out_tag, TAG_BYTE_LEN, tag, TAG_BYTE_LEN)) { // tag
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }
    if (!ippcp_is_mem_eq(out_ptext, MSG_BYTE_LEN, ptext, MSG_BYTE_LEN)) { // ptext
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
