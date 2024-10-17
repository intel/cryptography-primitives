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

#include "hash/pcphashmethod_rmf.h"

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
static const Ipp8u msg[] = { 0x2f,0xa4,0x3a,0x14,0xae,0x50,0x05,0x07,0xde,0xb9,0x5a,0xb5,0xbd,0x32,0xb0,0xfe };
// key
static const Ipp8u key[] = { 0xac,0x68,0x6b,0xa0,0xf1,0xa5,0x1b,0x4e,0xc4,0xf0,0xb3,0x04,0x92,0xb7,0xf5,0x56 };
// known tag
static const Ipp8u tag[] = { 0x00,0x85,0x32,0xa5,0x3d,0x0c,0x0a,0xb2,0x20,0x27,0xae,0x24,0x90,0x23,0x37,0x53,
                             0x74,0xe2,0x23,0x9b,0x95,0x96,0x09,0xe8,0x33,0x9b,0x05,0xa1,0x57,0x42,0xa6,0x75 };

static const int msgByteLen  = sizeof(msg);
static const int keyByteSize = sizeof(key);

#define IPPCP_TAG_BYTE_SIZE (sizeof(tag))

IPPFUN(fips_test_status, fips_selftest_ippsHMAC_rmf_get_size, (int *pBuffSize)) {
    /* return bad status if input pointer is NULL */
    IPP_BADARG_RET((NULL == pBuffSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int ctx_size = 0;
    sts = ippsHMACGetSize_rmf(&ctx_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    ctx_size += IPPCP_HMAC_ALIGNMENT;

    int hash_method_size = 0;
    sts = ippsHashMethodGetSize(&hash_method_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    
    *pBuffSize = ctx_size + hash_method_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsHMACUpdate_rmf, (Ipp8u *pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */
    int internalMemMgm = 0;
    int ctx_size = 0;
    sts = fips_selftest_ippsHMAC_rmf_get_size(&ctx_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, ctx_size, IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)

    /* output hash */
    Ipp8u outTagBuff[IPPCP_TAG_BYTE_SIZE];
    Ipp8u outTagFinBuff[IPPCP_TAG_BYTE_SIZE];

    int hash_method_size = 0;
    sts = ippsHashMethodGetSize(&hash_method_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    IppsHashMethod* locMethod = (IppsHashMethod*)(pBuffer);
    sts = ippsHashMethodSet_SHA256_TT(locMethod);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* context */
    IppsHMACState_rmf* pCtx = (IppsHMACState_rmf*)(IPP_ALIGNED_PTR(pBuffer + hash_method_size, IPPCP_HMAC_ALIGNMENT));
    /* context initialization */
    sts = ippsHMACGetSize_rmf(&ctx_size);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsHMACInit_rmf(key, keyByteSize, pCtx, locMethod);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* function call */
    sts = ippsHMACUpdate_rmf(msg, msgByteLen, pCtx);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsHMACGetTag_rmf(outTagBuff, IPPCP_TAG_BYTE_SIZE, pCtx);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    sts = ippsHMACFinal_rmf(outTagFinBuff, IPPCP_TAG_BYTE_SIZE, pCtx);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* compare output to known answer */
    int isEqual;
    isEqual  = ippcp_is_mem_eq(outTagBuff, IPPCP_TAG_BYTE_SIZE, tag, IPPCP_TAG_BYTE_SIZE);
    isEqual &= ippcp_is_mem_eq(outTagFinBuff, IPPCP_TAG_BYTE_SIZE, tag, IPPCP_TAG_BYTE_SIZE);

    if (!isEqual) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsHMACMessage_rmf, (void))
{
    IppStatus sts = ippStsNoErr;
    /* output hash */
    Ipp8u outTagBuff[IPPCP_TAG_BYTE_SIZE];
    Ipp8u hashMethodArr[sizeof(IppsHashMethod)];

    IppsHashMethod* locMethod = (IppsHashMethod*)hashMethodArr;
    sts = ippsHashMethodSet_SHA256_TT(locMethod);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* function call */
    sts = ippsHMACMessage_rmf(msg, msgByteLen, key, keyByteSize, outTagBuff, IPPCP_TAG_BYTE_SIZE, locMethod);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    if (!ippcp_is_mem_eq(outTagBuff, IPPCP_TAG_BYTE_SIZE, tag, IPPCP_TAG_BYTE_SIZE)) {
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    return IPPCP_ALGO_SELFTEST_OK;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
