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
 * taken from the regular known-answer testing
 */
// message
static const Ipp8u msg[] = "abc";

// known digests
static const
Ipp8u sha256_md[] = "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
                    "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad";
static const
Ipp8u sha512_md[] = "\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31"
                    "\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a"
                    "\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd"
                    "\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f";

static const int msgByteLen = sizeof(msg)-1;

#define IPP_SHA256_DIGEST_BYTESIZE  (IPP_SHA256_DIGEST_BITSIZE/8)
#define IPP_SHA512_DIGEST_BYTESIZE  (IPP_SHA512_DIGEST_BITSIZE/8)

/*
 * Since ippcp's implementation of hashes reuses each other, only two methods -
 * ippsHashMethod_SHA256 and ippsHashMethod_SHA512 may be tested:
 *	 CAST for SHA-256 is required;
 *	 CAST for SHA-224 is covered by CAST for SHA-256;
 *	 CAST for SHA-512 is required;
 *	 CAST for SHA-512/224 and SHA-512/256 are covered by CAST for SHA-512;
 *	 CAST for SHA-384 is covered by CAST for SHA-512;
 */

static IppStatus selftestSetTestingMethod(const IppHashAlgId hashAlgIdIn, IppsHashMethod* locMethod, 
                                                Ipp32u* hashSize, Ipp8u** pMD) {
    IppStatus sts = ippStsNoErr;
    switch (hashAlgIdIn)
    {
        case IPP_ALG_HASH_SHA224:
        case IPP_ALG_HASH_SHA256:
                    {
                        sts = ippsHashMethodSet_SHA256_TT(locMethod);
                        *hashSize = IPP_SHA256_DIGEST_BYTESIZE;
                        *pMD = (Ipp8u*)sha256_md;
                        return sts;
                    }
        case IPP_ALG_HASH_SHA384:
        case IPP_ALG_HASH_SHA512_224:
        case IPP_ALG_HASH_SHA512_256:
        case IPP_ALG_HASH_SHA512:
                    {
                        sts = ippsHashMethodSet_SHA512(locMethod);
                        *hashSize = IPP_SHA512_DIGEST_BYTESIZE;
                        *pMD = (Ipp8u*)sha512_md;
                        return sts;
                    }
        default: break;
    }

    return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
}

IPPFUN(fips_test_status, fips_selftest_ippsHash_rmf_get_size, (int *pBuffSize)) {
    /* return bad status if input pointer is NULL */
    IPP_BADARG_RET((NULL == pBuffSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int ctx_size = 0;
    sts = ippsHashGetSize_rmf(&ctx_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    ctx_size += IPPCP_HASH_ALIGNMENT;

    int hash_method_size = 0;
    sts = ippsHashMethodGetSize(&hash_method_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    
    *pBuffSize = ctx_size + hash_method_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsHashUpdate_rmf, (IppHashAlgId hashAlgId, Ipp8u *pBuffer))
{
    IppStatus sts = ippStsNoErr;

    /* check input pointers and allocate memory in "use malloc" mode */
    int internalMemMgm = 0;

    int ctx_size = 0;
    sts = ippsHashGetSize_rmf(&ctx_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    ctx_size += IPPCP_HASH_ALIGNMENT;

    int hash_method_size = 0;
    sts = ippsHashMethodGetSize(&hash_method_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    BUF_CHECK_NULL_AND_ALLOC(pBuffer, internalMemMgm, (ctx_size + hash_method_size + IPPCP_HASH_ALIGNMENT), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR)


    Ipp32u locHashByteSize = 0;
    Ipp8u* md = NULL;
    IppsHashMethod* locMethod = (IppsHashMethod*)(pBuffer + ctx_size + IPPCP_HASH_ALIGNMENT);

    sts = selftestSetTestingMethod(hashAlgId, locMethod, &locHashByteSize, &md);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    /* output hash */
    Ipp8u outHashBuff[IPP_SHA512_DIGEST_BYTESIZE];
    Ipp8u outTagBuff[IPP_SHA512_DIGEST_BYTESIZE];
    /* context */
    IppsHashState_rmf* hashCtx = (IppsHashState_rmf*)(IPP_ALIGNED_PTR(pBuffer, IPPCP_HASH_ALIGNMENT));

    /* context initialization */
    sts = ippsHashInit_rmf(hashCtx, locMethod);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* function call */
    sts = ippsHashUpdate_rmf(msg, msgByteLen, hashCtx);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsHashGetTag_rmf(outTagBuff, (int)locHashByteSize, hashCtx);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsHashFinal_rmf(outHashBuff, hashCtx);
    if (sts != ippStsNoErr) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    /* compare output to known answer */
    int isEqual;
    isEqual  = ippcp_is_mem_eq(outTagBuff, locHashByteSize, md, locHashByteSize);
    isEqual &= ippcp_is_mem_eq(outHashBuff, locHashByteSize, md, locHashByteSize);

    if (!isEqual) {
        MEMORY_FREE(pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE(pBuffer, internalMemMgm)
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsHashMessage_rmf, (IppHashAlgId hashAlgId))
{
    IppStatus sts = ippStsNoErr;

    Ipp32u locHashByteSize = 0;
    Ipp8u* md = NULL;
    Ipp8u hashMethodArr[sizeof(IppsHashMethod)];

    IppsHashMethod* locMethod = (IppsHashMethod*)hashMethodArr;
    sts = selftestSetTestingMethod(hashAlgId, locMethod, &locHashByteSize, &md);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    /* output hash */
    Ipp8u outHashArr[IPP_SHA512_DIGEST_BYTESIZE];

    sts = ippsHashMessage_rmf(msg, msgByteLen, outHashArr, locMethod);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    /* compare output to known answer */
    if (!ippcp_is_mem_eq(outHashArr, locHashByteSize, md, locHashByteSize)) {
        return IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    return IPPCP_ALGO_SELFTEST_OK;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
