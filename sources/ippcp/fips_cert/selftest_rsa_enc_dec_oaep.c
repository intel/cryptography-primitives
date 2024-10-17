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
#include "fips_cert_internal/bn_common.h"

/*
 * KAT
 * vectors are taken from Wycheproof testing
*/
// KAT plaintext
__ALIGN64 static const Ipp8u pMsg[]  = { 0x31,0x32,0x33,0x34,0x30,0x30 };
// KAT seed (all 1)
__ALIGN64 static const Ipp8u seed[]  = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                                       "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                                       "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                                       "\xff\xff";
// KAT ciphertext
__ALIGN64 static const Ipp8u ctext[] = { 0x50,0xc2,0x3e,0x2a,0xd6,0xe3,0xf3,0xb1,0x0a,0x57,0x16,0xcb,0xf6,0x0e,0xfc,0xc9,
                                         0xf6,0x6d,0x2c,0x6f,0x17,0xbf,0x05,0x0b,0xa0,0x15,0x3b,0x87,0x7b,0xa2,0x75,0x5e,
                                         0x8a,0x0d,0x54,0x06,0x00,0x34,0x56,0x22,0x66,0x15,0x57,0x44,0xef,0x80,0x54,0x7b,
                                         0x8a,0xf7,0x77,0xb0,0xff,0x76,0x4f,0xbb,0x12,0xba,0xae,0x49,0xd0,0x2b,0x4f,0x6d,
                                         0x65,0xb6,0xcd,0x8f,0x0a,0x39,0x78,0x39,0x10,0x1d,0x32,0xae,0x16,0x3f,0xf2,0xe6,
                                         0x07,0x27,0x48,0xd6,0xb8,0x01,0x7e,0x5e,0x73,0xe3,0x32,0xd5,0x3f,0x4e,0x91,0xfe,
                                         0x62,0x33,0xa8,0x2d,0xbf,0x54,0xf3,0x14,0x6b,0x48,0x98,0x03,0x57,0x5c,0x5e,0xa3,
                                         0x7a,0xb5,0x5a,0x9e,0xa7,0xea,0xe4,0x7a,0xd4,0xf1,0x72,0x7d,0x45,0x82,0x2b,0x56,
                                         0x9c,0xd6,0xe5,0xd4,0xb6,0xab,0x75,0x98,0x50,0x94,0x81,0x86,0x61,0x6b,0x5d,0xa2,
                                         0xa9,0xa3,0x16,0xf5,0x7d,0x89,0x9f,0x91,0x93,0x4b,0xbb,0x27,0xed,0xcd,0xfa,0x19,
                                         0x53,0x2b,0xa1,0xc0,0x1f,0x37,0x24,0x73,0x8d,0xaf,0xfd,0xd8,0x8c,0x9a,0x18,0x56,
                                         0x2e,0xbc,0xbc,0x49,0x18,0x5b,0x0a,0x81,0x74,0x07,0x90,0x34,0x76,0xd4,0x42,0xc4,
                                         0x24,0xc8,0x1b,0x63,0xae,0xb8,0xf9,0xd1,0xb1,0x84,0x75,0x6e,0x0c,0xc0,0xa3,0x81,
                                         0xea,0xba,0x45,0xa8,0x5c,0x8b,0xbc,0x67,0x70,0xfd,0x04,0x7f,0xf1,0xa6,0x40,0x4a,
                                         0x38,0x45,0x99,0xfb,0xbd,0x6a,0x40,0xb2,0x12,0xa0,0x66,0xe2,0x3f,0x6a,0x15,0xcf,
                                         0x13,0xe4,0x2c,0x0e,0xa8,0x8c,0x71,0x0e,0x4d,0x70,0xc6,0x12,0x07,0x49,0x68,0xe5 };
// KAT modulus, public and private exponents
__ALIGN64 static const Ipp8u dataN[] = { 0xd5,0xb9,0x42,0xf7,0x83,0x02,0x82,0xf7,0x9c,0x2e,0x4c,0x5b,0x1f,0x3d,0x45,0x6f,
                                         0x06,0x73,0xe7,0x30,0xa5,0xe5,0x02,0x9a,0x3b,0x7d,0x80,0x62,0x9a,0x56,0x12,0x5d,
                                         0xa4,0xc1,0xf7,0xc0,0x5a,0x4e,0x2c,0xc2,0x9b,0x5d,0x00,0x75,0x79,0x5e,0xf8,0xf9,
                                         0xd8,0x60,0xd4,0x79,0xae,0x9c,0x4d,0x1b,0xba,0xcb,0x8b,0x69,0x48,0x6f,0x81,0x69,
                                         0x19,0x5a,0x97,0x90,0xf5,0x22,0x64,0x12,0xf1,0xa0,0xad,0x09,0x3e,0xfc,0x7a,0xfd,
                                         0x05,0xaf,0x8d,0x87,0xeb,0x11,0x54,0xed,0xd4,0x95,0x34,0x5d,0x5b,0x14,0x03,0x4c,
                                         0x6b,0xce,0x1e,0x4d,0xde,0x82,0xbe,0x12,0x5a,0x94,0x8d,0xa0,0xec,0xfc,0xd0,0x21,
                                         0xc0,0xf5,0x66,0x42,0x59,0x58,0x96,0x7d,0x9c,0xe0,0x28,0x04,0x61,0xda,0x22,0x4c,
                                         0x81,0xd9,0x15,0x96,0x29,0x81,0xed,0x90,0xf4,0x26,0xce,0x8d,0x6a,0xa2,0x1f,0x7a,
                                         0x39,0x29,0xa0,0xe1,0x17,0x8f,0xff,0x3e,0xa0,0x13,0x53,0x76,0xe9,0x2f,0x4a,0x25,
                                         0x8e,0xc9,0x48,0x6e,0xe4,0x42,0x3e,0x3d,0x7f,0x24,0xe8,0x15,0x9c,0xf7,0x20,0xcd,
                                         0xfa,0x53,0x12,0x1a,0x71,0xa7,0xd8,0x2e,0x51,0x92,0xdb,0x89,0x31,0x39,0xab,0xb5,
                                         0x97,0x50,0x84,0xc8,0xea,0xd6,0x89,0x9e,0x42,0x69,0xb4,0x03,0x59,0xf6,0x00,0x17,
                                         0x5a,0xef,0xb6,0x25,0x03,0xd8,0x78,0x18,0xd3,0xaf,0x7c,0x3f,0x6d,0x74,0xf9,0x37,
                                         0xe6,0x24,0x22,0xe8,0xfe,0xa1,0x4f,0x09,0x17,0xf7,0xbe,0x2e,0x46,0x5b,0x8a,0x4a,
                                         0x51,0x50,0x35,0x51,0x71,0x56,0x45,0x6e,0xf9,0xa5,0x0a,0x7d,0xa0,0x51,0xb4,0xa2 };
__ALIGN64 static const Ipp8u dataD[] = { 0xc1,0x67,0xc4,0x89,0x72,0xbe,0xec,0xb1,0xb7,0x1b,0x17,0xdf,0xdc,0xec,0x0e,0x72,
                                         0x00,0xb7,0xf3,0xfe,0xc6,0x04,0x6d,0xf6,0xd6,0xb0,0x85,0x09,0xf5,0x15,0xe7,0xba,
                                         0xf8,0xe6,0xba,0x50,0x69,0xa7,0x8d,0xbc,0x59,0x12,0xc0,0xaf,0xc5,0xf4,0xdf,0xb8,
                                         0x94,0xee,0xe7,0x26,0xa1,0xe5,0x73,0x86,0x6c,0x3b,0xc4,0xd5,0x4a,0xdb,0xe8,0x95,
                                         0x59,0xa9,0x51,0xb6,0xa8,0x9e,0xdb,0xfb,0xc8,0x3a,0x4c,0x07,0x1c,0xd0,0xac,0xa1,
                                         0x0a,0x05,0x51,0x9f,0x38,0x97,0xc1,0x4f,0x23,0x2b,0x75,0x0d,0xbf,0x0b,0xae,0x29,
                                         0xec,0x33,0x62,0xb9,0x96,0x6c,0xf7,0x99,0x43,0xff,0x1e,0x28,0xd9,0x1e,0xcc,0xe6,
                                         0xc2,0x09,0x99,0x5b,0xe0,0x5a,0xd4,0xfd,0xa0,0x66,0x43,0xf4,0x37,0xf5,0x7b,0x51,
                                         0xee,0xeb,0x21,0x78,0x2d,0x24,0x54,0x66,0xff,0xca,0xc8,0x3f,0xac,0x93,0x7d,0x6f,
                                         0x13,0x9f,0x7c,0x79,0x4c,0x05,0xb5,0xff,0xaa,0xaa,0x20,0x10,0xde,0x41,0x47,0x4b,
                                         0x0b,0xe0,0xdb,0x19,0xbf,0xdb,0x42,0xe0,0xcd,0x4a,0xdb,0x67,0x09,0xc1,0xe7,0xc4,
                                         0x99,0xe8,0xc4,0x10,0x03,0x11,0x2e,0x23,0x90,0xb3,0x04,0x72,0xb1,0x68,0x7a,0xac,
                                         0xe2,0x4f,0xc8,0xce,0xcf,0x77,0xf4,0x6f,0x3f,0x82,0x05,0x3d,0xac,0x4d,0x3a,0x54,
                                         0x64,0x9f,0x13,0xe7,0x0a,0xfa,0x0b,0xa0,0xc4,0xf3,0xc6,0xef,0x88,0xfa,0xa4,0x3c,
                                         0x57,0xb7,0x66,0x3c,0x5b,0x6a,0x30,0x9b,0x81,0xee,0xdc,0x9d,0xcb,0x2c,0x17,0xa7,
                                         0xc3,0x31,0xcd,0x3e,0x05,0x52,0x8e,0x26,0x27,0x2a,0x7b,0x56,0xf3,0xee,0x27,0x76 };
__ALIGN64 static const Ipp8u dataE[] = { 0x01, 0x00, 0x01 };


static const unsigned int pubExpBitSize   = 17;
static const unsigned int privExpBitSize  = 2048;
static const unsigned int modulusBitSize  = 2048;

#define IPPCP_MSG_BYTE_LEN       sizeof(pMsg)
#define IPPCP_CTEXT_BYTE_LEN     sizeof(ctext)
#define IPPCP_PRIV_EXP_WORD_SIZE (IPPCP_BITSIZE_2_WORDSIZE(privExpBitSize))
#define IPPCP_PUB_EXP_WORD_SIZE  (IPPCP_BITSIZE_2_WORDSIZE(pubExpBitSize))
#define IPPCP_MODULUS_WORD_SIZE  (IPPCP_BITSIZE_2_WORDSIZE(modulusBitSize))

IPPFUN(fips_test_status, fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size_keys, (int *pKeysBufferSize))
{
    /* return bad status if input pointer is NULL */
    IPP_BADARG_RET((NULL == pKeysBufferSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int total_size = 0;
    int tmp_size   = 0;

    sts = ippsBigNumGetSize(IPPCP_PUB_EXP_WORD_SIZE, &tmp_size);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    total_size += (tmp_size + IPPCP_BN_ALIGNMENT); // E

    sts = ippsBigNumGetSize(IPPCP_PRIV_EXP_WORD_SIZE, &tmp_size);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    total_size += (tmp_size + IPPCP_BN_ALIGNMENT); // D

    sts = ippsBigNumGetSize(IPPCP_MODULUS_WORD_SIZE, &tmp_size);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    total_size += (tmp_size + IPPCP_BN_ALIGNMENT); // N

    sts = ippsRSA_GetSizePublicKey(modulusBitSize, pubExpBitSize, &tmp_size);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    total_size += (tmp_size + IPPCP_RSA_ALIGNMENT); // pPubKey

    sts = ippsRSA_GetSizePrivateKeyType1(modulusBitSize, privExpBitSize, &tmp_size);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    total_size += (tmp_size + IPPCP_RSA_ALIGNMENT); // pPrivKey

    *pKeysBufferSize = total_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size, (int *pBufferSize, Ipp8u *pKeysBuffer))
{
    /* return bad status if input pointers are NULL */
    IPP_BADARG_RET((NULL == pBufferSize) || (NULL == pKeysBuffer), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int total_size = 0;

    Ipp8u* pLocKeysBuffer = pKeysBuffer;

    /* Initialize BigNumber-s */
    int eByteSize;
    sts = ippsBigNumGetSize(IPPCP_PUB_EXP_WORD_SIZE, &eByteSize);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnE = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += eByteSize;

    int dByteSize;
    sts = ippsBigNumGetSize(IPPCP_PRIV_EXP_WORD_SIZE, &dByteSize);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnD = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += dByteSize;

    int nByteSize;
    sts = ippsBigNumGetSize(IPPCP_MODULUS_WORD_SIZE, &nByteSize);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnN = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += nByteSize;

    sts = ippcp_init_set_bn(bnE, IPPCP_PUB_EXP_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)dataE, IPPCP_PUB_EXP_WORD_SIZE);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    sts = ippcp_init_set_bn(bnD, IPPCP_PRIV_EXP_WORD_SIZE, ippBigNumPOS, (const Ipp32u *)dataD, IPPCP_PRIV_EXP_WORD_SIZE);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    sts = ippcp_init_set_bn(bnN, IPPCP_MODULUS_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)dataN, IPPCP_MODULUS_WORD_SIZE);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;

    /* Initialize key pair - necessary to obtain signature size */
    // private key
    int privKeyByteSize = 0;
    sts = ippsRSA_GetSizePrivateKeyType1(modulusBitSize, privExpBitSize, &privKeyByteSize);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPrivateKeyState* pPrivKey = (IppsRSAPrivateKeyState*)pLocKeysBuffer;
    sts = ippsRSA_InitPrivateKeyType1(modulusBitSize, privExpBitSize, pPrivKey, privKeyByteSize);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    pLocKeysBuffer+=privKeyByteSize;

    // public key
    int pubKeyByteSize = 0;
    sts = ippsRSA_GetSizePublicKey(modulusBitSize, pubExpBitSize, &pubKeyByteSize);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPublicKeyState* pPubKey = (IppsRSAPublicKeyState*)pLocKeysBuffer;
    sts = ippsRSA_InitPublicKey(modulusBitSize, pubExpBitSize, pPubKey, pubKeyByteSize);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;

    /* Set key pair */
    sts = ippsRSA_SetPublicKey(bnN, bnE, pPubKey);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    sts = ippsRSA_SetPrivateKeyType1(bnN, bnD, pPrivKey);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;

    /* RSA decryption and encryption buffers */
    int decBufSize;
    sts = ippsRSA_GetBufferSizePrivateKey(&decBufSize, pPrivKey);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    int encBufSize;
    sts = ippsRSA_GetBufferSizePublicKey(&encBufSize, pPubKey);
    if(sts != ippStsNoErr) return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;

    total_size = IPP_MAX(decBufSize, encBufSize) + IPPCP_RSA_ALIGNMENT;


    /* Add an extra memory for the hash method*/
    int hash_method_size = 0;
    sts = ippsHashMethodGetSize(&hash_method_size);
    if (sts != ippStsNoErr) { return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR; }

    *pBufferSize = total_size + hash_method_size;

    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsRSAEncrypt_OAEP_rmf, (Ipp8u *pBuffer, Ipp8u *pKeysBuffer))
{
    IppStatus sts = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    /* Internal memory allocation feature */
    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if(pBuffer == NULL || pKeysBuffer == NULL) {
        internalMemMgm = 1;

        int keysBuffSize = 0;
        fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size_keys(&keysBuffSize);
        pKeysBuffer = malloc((size_t)keysBuffSize);

        int dataBuffSize = 0;
        fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size(&dataBuffSize, pKeysBuffer);
        pBuffer = malloc((size_t)dataBuffSize);
    }
#else
    IPP_BADARG_RET((NULL == pBuffer) || (NULL == pKeysBuffer), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    /* Buffer for the encrypted text */
    Ipp8u OutCtxt[IPPCP_CTEXT_BYTE_LEN];
    Ipp8u* pOutCtxt = OutCtxt;

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

    sts = ippcp_init_set_bn(bnE, IPPCP_PUB_EXP_WORD_SIZE,  ippBigNumPOS, (const Ipp32u *)dataE, IPPCP_PUB_EXP_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippcp_init_set_bn(bnN, IPPCP_MODULUS_WORD_SIZE, ippBigNumPOS, (const Ipp32u *)dataN, IPPCP_MODULUS_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Initialize public key */
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

    /* Set public key */
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

    /* RSA encryption */
    int encBufSize;
    sts = ippsRSA_GetBufferSizePublicKey(&encBufSize, pPubKey);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    Ipp8u* encScratchBuffer = (IPP_ALIGNED_PTR(pBuffer + hash_method_size, IPPCP_RSA_ALIGNMENT));

    sts = ippsRSAEncrypt_OAEP_rmf(pMsg, IPPCP_MSG_BYTE_LEN, 0, 0, seed, pOutCtxt, pPubKey,
                                  locMethod, encScratchBuffer);

    int sigFlagErr = ippcp_is_mem_eq(ctext, IPPCP_CTEXT_BYTE_LEN, pOutCtxt, IPPCP_CTEXT_BYTE_LEN);
    if(1 != sigFlagErr || sts != ippStsNoErr) {
        test_result = IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
    return test_result;
}

IPPFUN(fips_test_status, fips_selftest_ippsRSADecrypt_OAEP_rmf, (Ipp8u *pBuffer, Ipp8u *pKeysBuffer))
{
    IppStatus sts = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    /* Internal memory allocation feature */
    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if(pBuffer == NULL || pKeysBuffer == NULL) {
        internalMemMgm = 1;

        int keysBuffSize = 0;
        fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size_keys(&keysBuffSize);
        pKeysBuffer = malloc((size_t)keysBuffSize);

        int dataBuffSize = 0;
        fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size(&dataBuffSize, pKeysBuffer);
        pBuffer = malloc((size_t)dataBuffSize);
    }
#else
    IPP_BADARG_RET((NULL == pBuffer) || (NULL == pKeysBuffer), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    /* Buffer for the deciphered text */
    Ipp8u OutPtxt[IPPCP_MSG_BYTE_LEN];
    Ipp8u* pOutPtxt = OutPtxt;

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

    int nByteSize;
    sts = ippsBigNumGetSize(IPPCP_MODULUS_WORD_SIZE, &nByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_BN_ALIGNMENT));
    IppsBigNumState* bnN = (IppsBigNumState *)pLocKeysBuffer;
    pLocKeysBuffer += nByteSize;

    sts = ippcp_init_set_bn(bnD, IPPCP_PRIV_EXP_WORD_SIZE, ippBigNumPOS, (const Ipp32u *)dataD, IPPCP_PRIV_EXP_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    sts = ippcp_init_set_bn(bnN, IPPCP_MODULUS_WORD_SIZE, ippBigNumPOS, (const Ipp32u *)dataN, IPPCP_MODULUS_WORD_SIZE);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Initialize private key */
    int privKeyByteSize = 0;
    sts = ippsRSA_GetSizePrivateKeyType1(modulusBitSize, privExpBitSize, &privKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    pLocKeysBuffer = (IPP_ALIGNED_PTR(pLocKeysBuffer, IPPCP_RSA_ALIGNMENT));
    IppsRSAPrivateKeyState* pPrivKey = (IppsRSAPrivateKeyState*)pLocKeysBuffer;
    sts = ippsRSA_InitPrivateKeyType1(modulusBitSize, privExpBitSize, pPrivKey, privKeyByteSize);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Set private key */
    sts = ippsRSA_SetPrivateKeyType1(bnN, bnD, pPrivKey);
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

    /* RSA decryption */
    int decBufSize;
    sts = ippsRSA_GetBufferSizePrivateKey(&decBufSize, pPrivKey);
    if(sts != ippStsNoErr) {
        MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    Ipp8u* decScratchBuffer = (IPP_ALIGNED_PTR(pBuffer + hash_method_size, IPPCP_RSA_ALIGNMENT));

    int ptxtLen;

    sts = ippsRSADecrypt_OAEP_rmf(ctext, 0, 0, pOutPtxt, &ptxtLen, pPrivKey,
                                  locMethod, decScratchBuffer);

    int sigFlagErr = ippcp_is_mem_eq(pMsg, IPPCP_MSG_BYTE_LEN, pOutPtxt, IPPCP_MSG_BYTE_LEN);
    if(1 != sigFlagErr || sts != ippStsNoErr) {
        test_result = IPPCP_ALGO_SELFTEST_KAT_ERR;
    }

    MEMORY_FREE_2(pKeysBuffer, pBuffer, memMgmFlag)
    return test_result;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
