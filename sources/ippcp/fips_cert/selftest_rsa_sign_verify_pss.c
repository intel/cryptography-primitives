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

#include <ippcp/fips_cert.h>
#include <fips_cert_internal/common.h>
#include <fips_cert_internal/bn_common.h>

/*
 * KAT
 * vectors are taken from FIPS 186 testing vectors set
*/
__ALIGN64 static const Ipp8u pPrivExp[] = { 0x9f,0x06,0xd2,0x01,0x39,0xfc,0x4f,0x7a,0x86,0x83,0xc2,0xc9,0x1c,0xe9,
                                            0xd3,0x0e,0x2b,0x87,0x5e,0x07,0x8e,0xa3,0xeb,0x3e,0xe3,0x13,0x5d,0x0b,
                                            0x40,0x9d,0x86,0xf4,0xdf,0xb4,0x72,0xd9,0xda,0x0a,0x24,0xdf,0x6b,0x90,
                                            0x7c,0x6c,0xd6,0xec,0x98,0xc6,0x5c,0x92,0x04,0x0c,0x24,0xe4,0xc3,0xe8,
                                            0xe3,0x20,0x31,0xba,0xc7,0x0f,0x32,0x9a,0x44,0xa2,0x41,0x9a,0xd2,0x1e,
                                            0xaf,0x91,0x2f,0x72,0x71,0x8c,0x0a,0xc9,0x93,0x10,0xcf,0x6a,0x02,0x95,
                                            0xb5,0x21,0x1f,0xa4,0x74,0xfe,0xe5,0x54,0xa0,0xed,0x65,0x93,0xba,0x33,
                                            0x2c,0xb6,0xc4,0x86,0x3e,0xfa,0xd3,0x98,0xc7,0x09,0xfa,0x50,0xa9,0xb3,
                                            0xc2,0x96,0xa7,0xb0,0xf5,0x4b,0x7e,0xbd,0xfe,0xea,0xa4,0x49,0x5f,0x3e,
                                            0xb6,0x54,0x7a,0xa3,0x2b,0x06,0xe9,0x03,0xc0,0xac,0xad,0xb2,0x5d,0xce,
                                            0x6d,0x12,0xd3,0x65,0x81,0x1a,0xd7,0x65,0x94,0x1e,0xbe,0x8a,0x74,0x2d,
                                            0xbb,0x78,0xc9,0x50,0x02,0x9d,0x5c,0x1e,0xfd,0x54,0x00,0x81,0xf7,0xc9,
                                            0x0d,0xc8,0x9d,0x1b,0x44,0x8a,0x53,0x95,0x4a,0x6c,0x06,0xc8,0x87,0x60,
                                            0x3c,0xb9,0xdd,0xe7,0x8c,0xdb,0x0d,0x17,0x67,0x79,0x9b,0xf3,0x43,0xa4,
                                            0xec,0x88,0x9b,0xfd,0xc9,0xc0,0xaf,0xff,0xa9,0x6b,0xe1,0x55,0x5f,0x7c,
                                            0x33,0x04,0x48,0x94,0xf7,0x7a,0xb9,0xd8,0x23,0x4a,0x4c,0x2d,0xa5,0xee,
                                            0x87,0x2a,0x30,0x15,0x47,0xab,0x74,0xe5,0x08,0x8f,0x48,0x28,0xd1,0x75,
                                            0x9b,0x37,0x75,0x88,0x08,0xde,0x7b,0x32,0x86,0x45,0xf9,0x32,0xd3,0xb4,
                                            0x6b,0x78,0xe5,0x49 };
__ALIGN64 static const Ipp8u pPubExp[]  = { 0x4f,0xc9,0x86 };
__ALIGN64 static const Ipp8u pModulus[] = { 0xef,0x05,0x18,0x6b,0x85,0xe9,0xc6,0x0f,0xfc,0xa3,0xde,0x11,0xeb,0x94,
                                            0x5c,0xaf,0x0a,0x45,0xad,0x50,0xa8,0xf1,0xd9,0x59,0x33,0x12,0x37,0xfd,
                                            0xe7,0x5f,0xe6,0x3e,0xac,0x43,0x6f,0xce,0xbe,0xb4,0x49,0xd5,0xf9,0xa7,
                                            0xe0,0x7e,0x5f,0xd7,0x66,0x64,0x94,0x5b,0x58,0x27,0xdd,0x0b,0xb4,0x12,
                                            0xc4,0x12,0xc0,0x0d,0xf4,0x05,0xf2,0xbe,0xa1,0x1c,0x12,0xf1,0x52,0xf3,
                                            0x3a,0xb5,0x90,0x87,0x28,0xf5,0xb4,0xb1,0xd1,0x31,0x33,0x94,0x3a,0x5a,
                                            0x63,0x3f,0x03,0x7f,0xca,0xda,0xf9,0xc7,0x01,0x66,0x89,0xea,0xff,0x2e,
                                            0xfd,0xd5,0x20,0xa6,0x89,0x1c,0xf8,0x36,0x8c,0xea,0xac,0x89,0x3a,0x35,
                                            0xbd,0x19,0xab,0xe2,0x37,0x19,0x17,0xd8,0xac,0x9c,0xe8,0x67,0xac,0x6b,
                                            0x6b,0x31,0x3d,0xcb,0xee,0x24,0xb7,0xf5,0x2f,0xe6,0x0a,0xdb,0x55,0x67,
                                            0xa3,0x3e,0x14,0x13,0x84,0xb2,0xff,0xeb,0x3e,0xff,0xd7,0x44,0xd9,0xe2,
                                            0x7b,0x15,0x13,0x11,0xc7,0xbe,0xc5,0x6b,0xb8,0x23,0x64,0x33,0x70,0x96,
                                            0xc9,0x09,0x6f,0xb2,0xb6,0x15,0xee,0x2f,0x2b,0xd4,0x26,0xcb,0xb9,0x2c,
                                            0x9c,0x74,0xe5,0x1d,0x58,0x90,0xd7,0xf9,0xb9,0x37,0x04,0x43,0x26,0xf8,
                                            0xe4,0x45,0xc4,0x7d,0xef,0x0f,0x6c,0x8b,0x17,0xc6,0x3b,0x57,0x81,0xd2,
                                            0x08,0xc3,0x52,0xa7,0xbc,0x59,0xca,0x59,0x93,0x77,0xbe,0x6a,0x12,0x8f,
                                            0x32,0xff,0x48,0x59,0xbb,0x0b,0x93,0x1a,0xfd,0xec,0x5f,0x10,0x13,0x2e,
                                            0x6c,0xd5,0x5d,0xf7,0x4c,0xf1,0xba,0x5d,0x1e,0x5e,0x76,0x9c,0x53,0xd8,
                                            0x58,0x2b,0x06,0xc5 };
__ALIGN64 static const Ipp8u pMsg[]     = { 0xdf,0xc2,0x26,0x04,0xb9,0x5d,0x15,0x32,0x80,0x59,0x74,0x5c,0x6c,0x98,
                                            0xeb,0x9d,0xfb,0x34,0x7c,0xf9,0xf1,0x70,0xaf,0xf1,0x9d,0xee,0xec,0x55,
                                            0x5f,0x22,0x28,0x5a,0x67,0x06,0xc4,0xec,0xbf,0x0f,0xb1,0x45,0x8c,0x60,
                                            0xd9,0xbf,0x91,0x3f,0xba,0xe6,0xf4,0xc5,0x54,0xd2,0x45,0xd9,0x46,0xb4,
                                            0xbc,0x5f,0x34,0xae,0xc2,0xac,0x6b,0xe8,0xb3,0x3d,0xc8,0xe0,0xe3,0xa9,
                                            0xd6,0x01,0xdf,0xd5,0x36,0x78,0xf5,0x67,0x44,0x43,0xf6,0x7d,0xf7,0x8a,
                                            0x3a,0x9e,0x09,0x33,0xe5,0xf1,0x58,0xb1,0x69,0xac,0x8d,0x1c,0x4c,0xd0,
                                            0xfb,0x87,0x2c,0x14,0xca,0x8e,0x00,0x1e,0x54,0x2e,0xa0,0xf9,0xcf,0xda,
                                            0x88,0xc4,0x2d,0xca,0xd8,0xa7,0x40,0x97,0xa0,0x0c,0x22,0x05,0x5b,0x0b,
                                            0xd4,0x1f };
__ALIGN64 static const Ipp8u pSig[]     = { 0x8b,0x46,0xf2,0xc8,0x89,0xd8,0x19,0xf8,0x60,0xaf,0x0a,0x6c,0x4c,0x88,
                                            0x9e,0x4d,0x14,0x36,0xc6,0xca,0x17,0x44,0x64,0xd2,0x2a,0xe1,0x1b,0x9c,
                                            0xcc,0x26,0x5d,0x74,0x3c,0x67,0xe5,0x69,0xac,0xcb,0xc5,0xa8,0x0d,0x4d,
                                            0xd5,0xf1,0xbf,0x40,0x39,0xe2,0x3d,0xe5,0x2a,0xec,0xe4,0x02,0x91,0xc7,
                                            0x5f,0x89,0x36,0xc5,0x8c,0x9a,0x2f,0x77,0xa7,0x80,0xbb,0xe7,0xad,0x31,
                                            0xeb,0x76,0x74,0x2f,0x7b,0x2b,0x8b,0x14,0xca,0x1a,0x71,0x96,0xaf,0x7e,
                                            0x67,0x3a,0x3c,0xfc,0x23,0x7d,0x50,0xf6,0x15,0xb7,0x5c,0xf4,0xa7,0xea,
                                            0x78,0xa9,0x48,0xbe,0xda,0xf9,0x24,0x24,0x94,0xb4,0x1e,0x1d,0xb5,0x1f,
                                            0x43,0x7f,0x15,0xfd,0x25,0x51,0xbb,0x5d,0x24,0xee,0xfb,0x1c,0x3e,0x60,
                                            0xf0,0x36,0x94,0xd0,0x03,0x3a,0x1e,0x0a,0x9b,0x9f,0x5e,0x4a,0xb9,0x7d,
                                            0x45,0x7d,0xff,0x9b,0x9d,0xa5,0x16,0xdc,0x22,0x6d,0x6d,0x65,0x29,0x50,
                                            0x03,0x08,0xed,0x74,0xa2,0xe6,0xd9,0xf3,0xc1,0x05,0x95,0x78,0x8a,0x52,
                                            0xa1,0xbc,0x06,0x64,0xae,0xdf,0x33,0xef,0xc8,0xba,0xdd,0x03,0x7e,0xb7,
                                            0xb8,0x80,0x77,0x2b,0xdb,0x04,0xa6,0x04,0x6e,0x9e,0xde,0xee,0x41,0x97,
                                            0xc2,0x55,0x07,0xfb,0x0f,0x11,0xab,0x1c,0x9f,0x63,0xf5,0x3c,0x88,0x20,
                                            0xea,0x84,0x05,0xcf,0xd7,0x72,0x16,0x92,0x47,0x5b,0x4d,0x72,0x35,0x5f,
                                            0xa9,0xa3,0x80,0x4f,0x29,0xe6,0xb6,0xa7,0xb0,0x59,0xc4,0x44,0x1d,0x54,
                                            0xb2,0x8e,0x4e,0xed,0x25,0x29,0xc6,0x10,0x3b,0x54,0x32,0xc7,0x13,0x32,
                                            0xce,0x74,0x2b,0xcc};
__ALIGN64 static const Ipp8u pSalt[]    = { 0xe1,0x25,0x6f,0xc1,0xee,0xef,0x81,0x77,0x3f,0xdd,0x54,0x65,0x7e,0x40,
                                            0x07,0xfd,0xe6,0xbc,0xb9,0xb1 };

static const unsigned int msgByteLen      = sizeof(pMsg);
static const unsigned int saltByteLen     = sizeof(pSalt);

static const unsigned int pubExpBitSize   = 24;
static const unsigned int privExpBitSize  = 2048;
static const unsigned int modulusBitSize  = 2048;
static const unsigned int primeBitsize    = 1024;

#define IPPCP_PUB_EXP_WORD_SIZE  (IPPCP_BITSIZE_2_WORDSIZE(pubExpBitSize))
#define IPPCP_PRIV_EXP_WORD_SIZE (IPPCP_BITSIZE_2_WORDSIZE(privExpBitSize))
#define IPPCP_MODULUS_WORD_SIZE  (IPPCP_BITSIZE_2_WORDSIZE(modulusBitSize))

IPPFUN(fips_test_status, fips_selftest_ippsRSASignVerify_PSS_rmf_get_size_keys, (int *pKeysBufferSize))
{
    /* return bad status if input pointer is NULL */
    IPP_BADARG_RET((NULL == pKeysBufferSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int total_size = 0;
    int tmp_size = 0;

    /* BIGNUMs sizes */
    sts = ippsBigNumGetSize(IPPCP_PRIV_EXP_WORD_SIZE, &tmp_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    total_size += tmp_size; // D

    sts = ippsBigNumGetSize(IPPCP_PUB_EXP_WORD_SIZE, &tmp_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    total_size += tmp_size; // E

    sts = ippsBigNumGetSize(IPPCP_MODULUS_WORD_SIZE, &tmp_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    total_size += tmp_size; // N

    /* Public and private keys context size */
    sts = ippsRSA_GetSizePublicKey(modulusBitSize, pubExpBitSize, &tmp_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    total_size += tmp_size; // pPubKey

    sts = ippsPrimeGetSize(primeBitsize,  &tmp_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    total_size += tmp_size; // pPrimeG

    sts = ippsPRNGGetSize(&tmp_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    total_size += tmp_size; // pRand

    sts = ippsRSA_GetSizePrivateKeyType1(modulusBitSize, privExpBitSize, &tmp_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    int tmp_size_2 = 0;
    sts = ippsRSA_GetSizePrivateKeyType2(primeBitsize, privExpBitSize - primeBitsize, &tmp_size_2);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    total_size += IPP_MAX(tmp_size, tmp_size_2); // pPrvKey

    *pKeysBufferSize = total_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsRSASignVerify_PSS_rmf_get_size, (int *pBufferSize, Ipp8u *pKeysBuffer))
{
    /* return bad status if input pointers are NULL */
    IPP_BADARG_RET((NULL == pKeysBuffer) || (NULL == pBufferSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int total_size = 0;

    Ipp8u *pLocKeysBuffer = pKeysBuffer;

    /* Initialize BigNumber-s */
    int dByteSize;
    sts = ippsBigNumGetSize(IPPCP_PRIV_EXP_WORD_SIZE, &dByteSize);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnD = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += dByteSize;

    int eByteSize;
    sts = ippsBigNumGetSize(IPPCP_PUB_EXP_WORD_SIZE, &eByteSize);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnE = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += eByteSize;

    int nByteSize;
    sts = ippsBigNumGetSize(IPPCP_MODULUS_WORD_SIZE, &nByteSize);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnN = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += nByteSize;

    sts = ippcp_init_set_bn(bnD, IPPCP_PRIV_EXP_WORD_SIZE, ippBigNumPOS, (const Ipp32u *)pPrivExp, IPPCP_PRIV_EXP_WORD_SIZE);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    sts = ippcp_init_set_bn(bnE, IPPCP_PUB_EXP_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)pPubExp,  IPPCP_PUB_EXP_WORD_SIZE);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    sts = ippcp_init_set_bn(bnN, IPPCP_MODULUS_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)pModulus, IPPCP_MODULUS_WORD_SIZE);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    /* Initialize public and private keys - necessary to obtain signature size */
    // public key
    int pubKeySize;
    sts = ippsRSA_GetSizePublicKey(modulusBitSize, pubExpBitSize, &pubKeySize);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPublicKeyState* pPubKey = (IppsRSAPublicKeyState*)pLocKeysBuffer;
    sts = ippsRSA_InitPublicKey(modulusBitSize, pubExpBitSize, pPubKey, pubKeySize);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    pLocKeysBuffer+=pubKeySize;
    // private key
    int privKeySize;
    sts = ippsRSA_GetSizePrivateKeyType1(modulusBitSize, privExpBitSize, &privKeySize);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPrivateKeyState* pPrvKey = (IppsRSAPrivateKeyState*)(pLocKeysBuffer);
    sts = ippsRSA_InitPrivateKeyType1(modulusBitSize, privExpBitSize, pPrvKey, privKeySize);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    pLocKeysBuffer+=privKeySize;

    sts = ippsRSA_GetSizePrivateKeyType2(primeBitsize, privExpBitSize - primeBitsize, &privKeySize);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    IppsRSAPrivateKeyState* pPrvKey2 = (IppsRSAPrivateKeyState*)(pLocKeysBuffer);
    sts = ippsRSA_InitPrivateKeyType2(primeBitsize, privExpBitSize - primeBitsize, pPrvKey2, privKeySize);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    int buffSizePrivKey2 = 0;
    sts = ippsRSA_GetBufferSizePrivateKey(&buffSizePrivKey2, pPrvKey2);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    /* set public and private keys */
    sts = ippsRSA_SetPublicKey(bnN, bnE, pPubKey);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    sts = ippsRSA_SetPrivateKeyType1(bnN, bnD, pPrvKey);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;

    /* RSA signature and verification buffers */
    int buffSizeSignVerify = 0;
    sts = ippsRSA_GetBufferSizePublicKey(&buffSizeSignVerify, pPubKey);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;

    // private
    int buffSizePrivKey1 = 0;
    sts = ippsRSA_GetBufferSizePrivateKey(&buffSizePrivKey1, pPrvKey);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;

    /* resize buffer */
    total_size = IPP_MAX(IPP_MAX(buffSizeSignVerify, buffSizePrivKey1), buffSizePrivKey2) + IPPCP_RSA_ALIGNMENT;

    /* Add an extra memory for the hash method*/
    int hash_method_size = 0;
    sts = ippsHashMethodGetSize(&hash_method_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
    total_size += hash_method_size;

    *pBufferSize = total_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsRSASign_PSS_rmf,(Ipp8u *pBuffer, Ipp8u *pKeysBuffer))
{
    IppStatus sts = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    /* Internal memory allocation feature */
    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if(pBuffer == NULL || pKeysBuffer == NULL) {
        internalMemMgm = 1;

        int keysBuffSize = 0;
        sts = fips_selftest_ippsRSASignVerify_PSS_rmf_get_size_keys(&keysBuffSize);
        if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
        pKeysBuffer = malloc((size_t)keysBuffSize);

        int dataBuffSize = 0;
        sts = fips_selftest_ippsRSASignVerify_PSS_rmf_get_size(&dataBuffSize, pKeysBuffer);
        if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
        pBuffer = malloc((size_t)dataBuffSize);
    }
#else
    IPP_BADARG_RET((NULL == pBuffer) || (NULL == pKeysBuffer), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    /* buffer for the generated signature */
    Ipp8u pOutSig[256] = {0};
    Ipp8u* pLocKeysBuffer = pKeysBuffer;

    /* Initialize BigNumber-s */
    int dByteSize;
    sts = ippsBigNumGetSize(IPPCP_PRIV_EXP_WORD_SIZE, &dByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnD = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += dByteSize;

    int eByteSize;
    sts = ippsBigNumGetSize(IPPCP_PUB_EXP_WORD_SIZE, &eByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnE = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += eByteSize;

    int nByteSize;
    sts = ippsBigNumGetSize(IPPCP_MODULUS_WORD_SIZE, &nByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnN = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += nByteSize;

    sts = ippcp_init_set_bn(bnD, IPPCP_PRIV_EXP_WORD_SIZE, ippBigNumPOS, (const Ipp32u *)pPrivExp, IPPCP_PRIV_EXP_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippcp_init_set_bn(bnE, IPPCP_PUB_EXP_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)pPubExp,  IPPCP_PUB_EXP_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippcp_init_set_bn(bnN, IPPCP_MODULUS_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)pModulus, IPPCP_MODULUS_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Initialize key pair */
    // private key
    int privKeyByteSize = 0;
    sts = ippsRSA_GetSizePrivateKeyType1(modulusBitSize, privExpBitSize, &privKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPrivateKeyState* pPrvKey = (IppsRSAPrivateKeyState*)pLocKeysBuffer;
    sts = ippsRSA_InitPrivateKeyType1(modulusBitSize, privExpBitSize, pPrvKey, privKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer += (privKeyByteSize);

    // public key
    int pubKeyByteSize = 0;
    sts = ippsRSA_GetSizePublicKey(modulusBitSize, pubExpBitSize, &pubKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPublicKeyState* pPubKey = (IppsRSAPublicKeyState*)pLocKeysBuffer;
    sts = ippsRSA_InitPublicKey(modulusBitSize, pubExpBitSize, pPubKey, pubKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* set public and private keys */
    sts = ippsRSA_SetPublicKey(bnN, bnE, pPubKey);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsRSA_SetPrivateKeyType1(bnN, bnD, pPrvKey);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Get memory offset and set Hash Method */
    int hash_method_size = 0;
    sts = ippsHashMethodGetSize(&hash_method_size);
    if (sts != ippStsNoErr) { 
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    IppsHashMethod* locMethod = (IppsHashMethod*)(pBuffer);
    sts = ippsHashMethodSet_SHA256_TT(locMethod);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* RSA Signature Generation */
    Ipp8u* pLocSignBuffer = (IPP_ALIGNED_PTR(pBuffer + hash_method_size, IPPCP_RSA_ALIGNMENT));

    sts = ippsRSASign_PSS_rmf(pMsg, msgByteLen, pSalt, saltByteLen, pOutSig, pPrvKey,
                              pPubKey, locMethod, pLocSignBuffer);

    int sigFlagErr = ippcp_is_mem_eq(pSig, sizeof(pSig), pOutSig, sizeof(pSig));
    if(1 != sigFlagErr || sts != ippStsNoErr) {
        test_result = IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
    return test_result;
}

IPPFUN(fips_test_status, fips_selftest_ippsRSAVerify_PSS_rmf,(Ipp8u *pBuffer, Ipp8u *pKeysBuffer))
{
    IppStatus sts = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    /* Internal memory allocation feature */
    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if(pBuffer == NULL || pKeysBuffer == NULL) {
        internalMemMgm = 1;

        int keysBuffSize = 0;
        sts = fips_selftest_ippsRSASignVerify_PSS_rmf_get_size_keys(&keysBuffSize);
        if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
        pKeysBuffer = malloc((size_t)keysBuffSize);

        int dataBuffSize = 0;
        sts = fips_selftest_ippsRSASignVerify_PSS_rmf_get_size(&dataBuffSize, pKeysBuffer);
        if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
        pBuffer = malloc((size_t)dataBuffSize);
    }
#else
    IPP_BADARG_RET((NULL == pBuffer) || (NULL == pKeysBuffer), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    Ipp8u* pLocKeysBuffer = pKeysBuffer;

    /* Initialize BigNumber-s */
    int eByteSize;
    sts = ippsBigNumGetSize(IPPCP_PUB_EXP_WORD_SIZE, &eByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnE = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += eByteSize;

    int nByteSize;
    sts = ippsBigNumGetSize(IPPCP_MODULUS_WORD_SIZE, &nByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnN = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += nByteSize;

    sts = ippcp_init_set_bn(bnE, IPPCP_PUB_EXP_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)pPubExp,  IPPCP_PUB_EXP_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippcp_init_set_bn(bnN, IPPCP_MODULUS_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)pModulus, IPPCP_MODULUS_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Initialize and set public key */
    int pubKeyByteSize = 0;
    sts = ippsRSA_GetSizePublicKey(modulusBitSize, pubExpBitSize, &pubKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPublicKeyState* pPubKey = (IppsRSAPublicKeyState*)pLocKeysBuffer;
    sts = ippsRSA_InitPublicKey(modulusBitSize, pubExpBitSize, pPubKey, pubKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippsRSA_SetPublicKey(bnN, bnE, pPubKey);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Get memory offset and set Hash Method */
    int hash_method_size = 0;
    sts = ippsHashMethodGetSize(&hash_method_size);
    if (sts != ippStsNoErr) { 
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    IppsHashMethod* locMethod = (IppsHashMethod*)(pBuffer);
    sts = ippsHashMethodSet_SHA256_TT(locMethod);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    Ipp8u* pLocVerifBuffer = (IPP_ALIGNED_PTR(pBuffer + hash_method_size, IPPCP_RSA_ALIGNMENT));

    /* RSA Signature Verification */
    int isValid;
    sts = ippsRSAVerify_PSS_rmf(pMsg,msgByteLen, pSig, &isValid, pPubKey,
                                locMethod, pLocVerifBuffer);

    if(!isValid || sts != ippStsNoErr)  {
        test_result = IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
    return test_result;
}

IPPFUN(fips_test_status, fips_selftest_ippsRSA_GenerateKeys,(Ipp8u *pBuffer, Ipp8u *pKeysBuffer))
{
    IppStatus sts = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    /* Internal memory allocation feature */
    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if(pBuffer == NULL || pKeysBuffer == NULL) {
        internalMemMgm = 1;

        int keysBuffSize = 0;
        sts = fips_selftest_ippsRSASignVerify_PSS_rmf_get_size_keys(&keysBuffSize);
        if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
        pKeysBuffer = malloc((size_t)keysBuffSize);

        int dataBuffSize = 0;
        sts = fips_selftest_ippsRSASignVerify_PSS_rmf_get_size(&dataBuffSize, pKeysBuffer);
        if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }
        pBuffer = malloc((size_t)dataBuffSize);
    }
#else
    IPP_BADARG_RET((NULL == pBuffer) || (NULL == pKeysBuffer), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    /* buffer for the generated signature */
    Ipp8u pOutSig[256] = {0};
    Ipp8u* pLocKeysBuffer = pKeysBuffer;

    /* Initialize BigNumber-s */
    int dByteSize;
    sts = ippsBigNumGetSize(IPPCP_PRIV_EXP_WORD_SIZE, &dByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnD = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += dByteSize;

    int eByteSize;
    sts = ippsBigNumGetSize(IPPCP_PUB_EXP_WORD_SIZE, &eByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnE = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += eByteSize;

    int nByteSize;
    sts = ippsBigNumGetSize(IPPCP_MODULUS_WORD_SIZE, &nByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnN = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += nByteSize;

    sts = ippcp_init_set_bn(bnD, IPPCP_PRIV_EXP_WORD_SIZE, ippBigNumPOS, (const Ipp32u *)pPrivExp, IPPCP_PRIV_EXP_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippcp_init_set_bn(bnE, IPPCP_PUB_EXP_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)pPubExp,  IPPCP_PUB_EXP_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippcp_init_set_bn(bnN, IPPCP_MODULUS_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)pModulus, IPPCP_MODULUS_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    // prime generator
    int size;
    sts = ippsPrimeGetSize(primeBitsize, &size);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    IppsPrimeState* pPrimeG = (IppsPrimeState*)(IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_GFP_ALIGNMENT));
    sts = ippsPrimeInit(primeBitsize, pPrimeG);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer += size;

    int privKey2ByteSize = 0;
    sts = ippsRSA_GetSizePrivateKeyType2(primeBitsize, privExpBitSize - primeBitsize, &privKey2ByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPrivateKeyState* pPrvKey2 = (IppsRSAPrivateKeyState*)pLocKeysBuffer;
    sts = ippsRSA_InitPrivateKeyType2(primeBitsize, privExpBitSize - primeBitsize, pPrvKey2, privKey2ByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer += (privKey2ByteSize);

    // initialize RNG
    int pRandSize;
    const int seedBitsize = 160;
    sts = ippsPRNGGetSize(&pRandSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    IppsPRNGState* pRand = (IppsPRNGState*)pLocKeysBuffer;
    sts = ippsPRNGInit(seedBitsize, pRand);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer += (pRandSize);

    // generate keys
    Ipp8u* pLocGenerateKeysBuffer = (IPP_ALIGNED_PTR(pBuffer, IPPCP_RSA_ALIGNMENT));
    sts = ippStsInsufficientEntropy;
    for(int loop_count = 0; loop_count < 100 && ippStsInsufficientEntropy == sts; ++loop_count) {
        sts = ippsRSA_GenerateKeys(bnE, bnN, bnE, bnD, pPrvKey2, pLocGenerateKeysBuffer, 0, pPrimeG, ippsPRNGen, pRand);
    }

    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    // public key
    int pubKeyByteSize = 0;
    sts = ippsRSA_GetSizePublicKey(modulusBitSize, pubExpBitSize, &pubKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPublicKeyState* pPubKey = (IppsRSAPublicKeyState*)pLocKeysBuffer;
    sts = ippsRSA_InitPublicKey(modulusBitSize, pubExpBitSize, pPubKey, pubKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* set public and private keys */
    sts = ippsRSA_SetPublicKey(bnN, bnE, pPubKey);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Get memory offset and set Hash Method */
    int hash_method_size = 0;
    sts = ippsHashMethodGetSize(&hash_method_size);
    if (sts != ippStsNoErr) { 
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    IppsHashMethod* locMethod = (IppsHashMethod*)(pBuffer);
    sts = ippsHashMethodSet_SHA256_TT(locMethod);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* RSA Signature Generation */
    Ipp8u* pLocSignBuffer = (IPP_ALIGNED_PTR(pBuffer + hash_method_size, IPPCP_RSA_ALIGNMENT));
    sts = ippsRSASign_PSS_rmf(pMsg, msgByteLen, pSalt, saltByteLen, pOutSig, pPrvKey2,
                              pPubKey, locMethod, pLocSignBuffer);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* RSA Signature Verification */
    int isValid;
    Ipp8u* pLocVerifBuffer = (IPP_ALIGNED_PTR(pBuffer + hash_method_size, IPPCP_RSA_ALIGNMENT));
    sts = ippsRSAVerify_PSS_rmf(pMsg,msgByteLen, pOutSig, &isValid, pPubKey,
                                locMethod, pLocVerifBuffer);

    if(!isValid || sts != ippStsNoErr) {
        test_result = IPPCP_ALGO_SELFTEST_KAT_ERR;
    }
    MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
    return test_result;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
