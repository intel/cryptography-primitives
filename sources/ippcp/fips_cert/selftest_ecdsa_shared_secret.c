/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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
#include "fips_cert_internal/bn_common.h"

/*
 * KAT
 * taken from wycheproof testing
 */

/* public */
static const Ipp8u pub_x[] = { 0x26, 0x4f, 0xe4, 0xaf, 0x31, 0xd7, 0x61, 0xfa, 0xfd, 0x0b, 0x8b,
                               0x86, 0x46, 0x70, 0xe0, 0x28, 0x24, 0x50, 0x0f, 0x5d, 0x71, 0x40,
                               0xa0, 0x85, 0xfe, 0x75, 0xaf, 0x72, 0x33, 0xbd, 0xd5, 0x62 };

static const Ipp8u pub_y[] = { 0xcf, 0x30, 0x4e, 0x01, 0x5a, 0x27, 0x7d, 0xa0, 0xb4, 0x72, 0x88,
                               0xc3, 0xc8, 0x41, 0xb7, 0x0e, 0x99, 0x13, 0x8d, 0xbf, 0xb5, 0x95,
                               0x5a, 0xcd, 0x81, 0x0a, 0xe7, 0xa9, 0x93, 0x3a, 0x33, 0xac };
/* private */
static const Ipp8u prv_key[] = { 0x46, 0xc3, 0x10, 0x2c, 0xe0, 0x52, 0x53, 0x7b, 0x64, 0x38, 0x41,
                                 0xf8, 0xae, 0x53, 0xbb, 0xfe, 0xd3, 0xbf, 0xce, 0x6b, 0x0a, 0x5b,
                                 0x85, 0x17, 0xab, 0x23, 0xa0, 0x89, 0x5c, 0x46, 0x12, 0x06 };
/* shared key */
static const Ipp8u sh_key[] = { 0x85, 0x42, 0x71, 0xe1, 0x95, 0x08, 0xbc, 0x93, 0x5a, 0xb2, 0x2b,
                                0x95, 0xcd, 0x2b, 0xe1, 0x3a, 0x0e, 0x78, 0x26, 0x5f, 0x52, 0x8b,
                                0x65, 0x8b, 0x32, 0x19, 0x02, 0x8b, 0x90, 0x0d, 0x02, 0x53 };


IPPFUN(fips_test_status,
       fips_selftest_ippsGFpECSharedSecretDH,
       (Ipp8u * pGFpBuff, Ipp8u* pGFpECBuff, Ipp8u* pDataBuff))
{
    IppStatus sts                = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    const unsigned int primeBitSize  = 256;
    const unsigned int primeWordSize = 8;

    /* Internal memory allocation feature */
    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if (pGFpBuff == NULL || pGFpECBuff == NULL || pDataBuff == NULL) {
        internalMemMgm = 1;

        int gfpBuffSize = 0;
        sts             = fips_selftest_ippsGFpECSignVerifyDSA_get_size_GFp_buff(&gfpBuffSize);
        if (sts != ippStsNoErr) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
        pGFpBuff = malloc((size_t)gfpBuffSize);

        int gfpECBuffSize = 0;
        sts = fips_selftest_ippsGFpECSignVerifyDSA_get_size_GFpEC_buff(&gfpECBuffSize, pGFpBuff);
        if (sts != ippStsNoErr) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
        pGFpECBuff = malloc((size_t)gfpECBuffSize);

        int dataBuffSize = 0;

        sts = fips_selftest_ippsGFpECSignVerifyDSA_get_size_data_buff(&dataBuffSize,
                                                                      pGFpBuff,
                                                                      pGFpECBuff);
        if (sts != ippStsNoErr) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
        pDataBuff = malloc((size_t)dataBuffSize);
    }
#else
    IPP_BADARG_RET((NULL == pGFpBuff) || (NULL == pGFpECBuff) || (NULL == pDataBuff),
                   IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    /* Init GFp context */
    IppsGFpState* pGF = (IppsGFpState*)(IPP_ALIGNED_PTR(pGFpBuff, IPPCP_GFP_ALIGNMENT));
    sts               = ippsGFpInitFixed(primeBitSize, ippsGFpMethod_p256r1(), pGF);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Init GFpEC context */
    IppsGFpECState* pEC = (IppsGFpECState*)(IPP_ALIGNED_PTR(pGFpECBuff, IPPCP_GFP_ALIGNMENT));
    sts                 = ippsGFpECInitStd256r1(pGF, pEC);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    Ipp8u* pLocDataBuff = pDataBuff;

    /* private key */
    int regKeyCtxByteSize;
    sts = ippsBigNumGetSize(primeWordSize, &regKeyCtxByteSize);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    IppsBigNumState* bnPrivate =
        (IppsBigNumState*)(IPP_ALIGNED_PTR(pLocDataBuff, IPPCP_GFP_ALIGNMENT));
    sts = ippcp_init_set_bn(bnPrivate,
                            primeWordSize,
                            ippBigNumPOS,
                            (const Ipp32u*)prv_key,
                            primeWordSize);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocDataBuff += regKeyCtxByteSize;

    /* shared key */
    int sharedKeyCtxByteSize;
    sts = ippsBigNumGetSize(primeWordSize, &sharedKeyCtxByteSize);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    IppsBigNumState* bnShared =
        (IppsBigNumState*)(IPP_ALIGNED_PTR(pLocDataBuff, IPPCP_GFP_ALIGNMENT));
    sts = ippcp_init_set_bn(bnShared,
                            primeWordSize,
                            ippBigNumPOS,
                            (const Ipp32u*)/*empty*/ prv_key,
                            primeWordSize);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocDataBuff += sharedKeyCtxByteSize;

    /* public key */
    // element
    int sizeElem;
    sts = ippsGFpElementGetSize(pGF, &sizeElem);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    IppsGFpElement* pubXElement =
        (IppsGFpElement*)(IPP_ALIGNED_PTR(pLocDataBuff, IPPCP_GFP_ALIGNMENT));
    sts = ippsGFpElementInit((Ipp32u*)pub_x, primeWordSize, pubXElement, pGF);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocDataBuff += sizeElem;

    IppsGFpElement* pubYElement =
        (IppsGFpElement*)(IPP_ALIGNED_PTR(pLocDataBuff, IPPCP_GFP_ALIGNMENT));
    sts = ippsGFpElementInit((Ipp32u*)pub_y, primeWordSize, pubYElement, pGF);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocDataBuff += sizeElem;

    // point
    int sizePoint;
    sts = ippsGFpECPointGetSize(pEC, &sizePoint);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    IppsGFpECPoint* regPublic =
        (IppsGFpECPoint*)(IPP_ALIGNED_PTR(pLocDataBuff, IPPCP_GFP_ALIGNMENT));
    sts = ippsGFpECPointInit(pubXElement, pubYElement, regPublic, pEC);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocDataBuff += sizePoint;

    /* Shared Key Generation */
    sts = ippsGFpECSharedSecretDH(bnPrivate, regPublic, bnShared, pEC, pLocDataBuff);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    Ipp8u pOut[sizeof(sh_key)];
    int len;

    IppsBigNumSGN sgn;
    sts = ippsGet_BN(&sgn, &len, (Ipp32u*)pOut, bnShared);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    int sigFlagErr;
    sigFlagErr = ippcp_is_mem_eq(sh_key, sizeof(sh_key), pOut, sizeof(sh_key));

    if (1 != sigFlagErr) {
        test_result = IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE_3(pGFpBuff, pGFpECBuff, pDataBuff, internalMemMgm)
    return test_result;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
