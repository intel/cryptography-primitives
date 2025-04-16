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

/*
 * KAT TEST
 * taken from Wycheproof testing
 */
// message
static const Ipp8u msg[] = { 0x61, 0x23, 0xc5, 0x56, 0xc5, 0xcc };
// key
static const Ipp8u key[] = { 0x48, 0x14, 0x40, 0x29, 0x85, 0x25, 0xcc, 0x26,
                             0x1f, 0x81, 0x59, 0x15, 0x9a, 0xed, 0xf6, 0x2d };
// known tag
static const Ipp8u tag[] = { 0xa2, 0x81, 0xe0, 0xd2, 0xd5, 0x37, 0x8d, 0xfd,
                             0xcc, 0x13, 0x10, 0xfd, 0x97, 0x82, 0xca, 0x56 };

static const int msgByteLen  = sizeof(msg);
static const int keyByteSize = sizeof(key);

#define IPPCP_TAG_BYTE_SIZE (sizeof(tag))

IPPFUN(fips_test_status, fips_selftest_ippsAES_CMAC_get_size, (int* pBuffSize))
{
    /* return bad status if input pointer is NULL */
    IPP_BADARG_RET((NULL == pBuffSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int ctx_size  = 0;
    sts           = ippsAES_CMACGetSize(&ctx_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    ctx_size += IPPCP_AES_ALIGNMENT;
    *pBuffSize = ctx_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsAES_CMACUpdate, (Ipp8u * pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */
    int internalMemMgm = 0;
    int ctx_size       = 0;
    sts                = fips_selftest_ippsAES_CMAC_get_size(&ctx_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* output hash */
    Ipp8u outTagBuff[IPPCP_TAG_BYTE_SIZE];
    Ipp8u outTagFinBuff[IPPCP_TAG_BYTE_SIZE];
    /* context */
    IppsAES_CMACState* pCtx = (IppsAES_CMACState*)(IPP_ALIGNED_PTR(pBuffer, IPPCP_AES_ALIGNMENT));

    /* context initialization */
    sts = ippsAES_CMACGetSize(&ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_CMACInit(key, keyByteSize, pCtx, ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* function call */
    sts = ippsAES_CMACUpdate(msg, msgByteLen, pCtx);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_CMACGetTag(outTagBuff, IPPCP_TAG_BYTE_SIZE, pCtx);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsAES_CMACFinal(outTagFinBuff, IPPCP_TAG_BYTE_SIZE, pCtx);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* compare output to known answer */
    int isEqual;
    isEqual = ippcp_is_mem_eq(outTagBuff, IPPCP_TAG_BYTE_SIZE, tag, IPPCP_TAG_BYTE_SIZE);
    isEqual &= ippcp_is_mem_eq(outTagFinBuff, IPPCP_TAG_BYTE_SIZE, tag, IPPCP_TAG_BYTE_SIZE);

    if (!isEqual) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
