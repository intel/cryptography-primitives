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

#ifndef IPPCP_FIPS_CERT_H
#define IPPCP_FIPS_CERT_H

#include <ippcp.h>
#include <ippcpdefs.h>

#if defined( __cplusplus )
extern "C" {
#endif

typedef int fips_test_status;
typedef int func_fips_approved;

#define IPPCP_ALGO_SELFTEST_OK           (0)
#define IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR (1)
#define IPPCP_ALGO_SELFTEST_KAT_ERR      (2)

/* Enc/Dec */
IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptDecrypt_get_size, (int *pBuffSize))

IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptCBC, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESDecryptCBC, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptCBC_CS1, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptCBC_CS2, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptCBC_CS3, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESDecryptCBC_CS1, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESDecryptCBC_CS2, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESDecryptCBC_CS3, (Ipp8u *pBuffer))

IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptCFB, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESDecryptCFB, (Ipp8u *pBuffer))

IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptOFB, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESDecryptOFB, (Ipp8u *pBuffer))

IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptCTR, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAESDecryptCTR, (Ipp8u *pBuffer))

IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptDecryptCCM_get_size, (int *pBuffSize))
IPPAPI(fips_test_status, fips_selftest_ippsAES_CCMEncrypt, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAES_CCMDecrypt, (Ipp8u *pBuffer))

IPPAPI(fips_test_status, fips_selftest_ippsAES_GCM_get_size, (int *pBufferSize))
IPPAPI(fips_test_status, fips_selftest_ippsAES_GCMEncrypt, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsAES_GCMDecrypt, (Ipp8u *pBuffer))

/* Selftests are disabled for now, since AES-XTS algorithm didn't pass CAVP testing */
// IPPAPI(fips_test_status, fips_selftest_ippsAESEncryptDecryptXTS_get_size, (int *pBuffSize))
// IPPAPI(fips_test_status, fips_selftest_ippsAES_XTSEncrypt, (Ipp8u *pBuffer))
// IPPAPI(fips_test_status, fips_selftest_ippsAES_XTSDecrypt, (Ipp8u *pBuffer))

IPPAPI(fips_test_status, fips_selftest_ippsAES_CMAC_get_size, (int *pBuffSize))
IPPAPI(fips_test_status, fips_selftest_ippsAES_CMACUpdate, (Ipp8u *pBuffer))

IPPAPI(fips_test_status, fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size_keys, (int *pKeysBufferSize))
IPPAPI(fips_test_status, fips_selftest_ippsRSAEncryptDecrypt_OAEP_rmf_get_size, (int *pBufferSize, Ipp8u *pKeysBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsRSAEncrypt_OAEP_rmf, (Ipp8u *pBuffer, Ipp8u *pKeysBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsRSADecrypt_OAEP_rmf, (Ipp8u *pBuffer, Ipp8u *pKeysBuffer))

/* Hashes */
IPPAPI(fips_test_status, fips_selftest_ippsHash_rmf_get_size, (int *pBuffSize))
IPPAPI(fips_test_status, fips_selftest_ippsHashUpdate_rmf, (IppHashAlgId hashAlgId, Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsHashMessage_rmf, (IppHashAlgId hashAlgId))

/* HMAC */
IPPAPI(fips_test_status, fips_selftest_ippsHMAC_rmf_get_size, (int *pBuffSize))
IPPAPI(fips_test_status, fips_selftest_ippsHMACUpdate_rmf, (Ipp8u *pBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsHMACMessage_rmf, (void))

/* RSA sign/verify */
IPPAPI(fips_test_status, fips_selftest_ippsRSASignVerify_PKCS1v15_rmf_get_size_keys, (int *pKeysBufferSize))
IPPAPI(fips_test_status, fips_selftest_ippsRSASignVerify_PKCS1v15_rmf_get_size, (int *pBufferSize, Ipp8u *pKeysBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsRSASign_PKCS1v15_rmf, (Ipp8u *pBuffer, Ipp8u *pKeysBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsRSAVerify_PKCS1v15_rmf, (Ipp8u *pBuffer, Ipp8u *pKeysBuffer))

IPPAPI(fips_test_status, fips_selftest_ippsRSASignVerify_PSS_rmf_get_size_keys, (int *pKeysBufferSize))
IPPAPI(fips_test_status, fips_selftest_ippsRSASignVerify_PSS_rmf_get_size, (int *pBufferSize, Ipp8u *pKeysBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsRSASign_PSS_rmf, (Ipp8u *pBuffer, Ipp8u *pKeysBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsRSAVerify_PSS_rmf, (Ipp8u *pBuffer, Ipp8u *pKeysBuffer))
IPPAPI(fips_test_status, fips_selftest_ippsRSA_GenerateKeys, (Ipp8u *pBuffer, Ipp8u *pKeysBuffer))

/* ECDSA sign/verify */
IPPAPI(fips_test_status, fips_selftest_ippsGFpECSignVerifyDSA_get_size_GFp_buff, (int *pGFpBuffSize))
IPPAPI(fips_test_status, fips_selftest_ippsGFpECSignVerifyDSA_get_size_GFpEC_buff, (int *pGFpECBuffSize, Ipp8u *pGFpBuff))
IPPAPI(fips_test_status, fips_selftest_ippsGFpECSignVerifyDSA_get_size_data_buff, (int *pDataBuffSize, Ipp8u *pGFpBuff, Ipp8u *pGFpECBuff))
IPPAPI(fips_test_status, fips_selftest_ippsGFpECSignDSA, (Ipp8u *pGFpBuff, Ipp8u *pGFpECBuff, Ipp8u *pDataBuff))
IPPAPI(fips_test_status, fips_selftest_ippsGFpECVerifyDSA, (Ipp8u *pGFpBuff, Ipp8u *pGFpECBuff, Ipp8u *pDataBuff))
IPPAPI(fips_test_status, fips_selftest_ippsGFpECPublicKey, (Ipp8u *pGFpBuff, Ipp8u *pGFpECBuff, Ipp8u *pDataBuff))
IPPAPI(fips_test_status, fips_selftest_ippsGFpECPrivateKey, (Ipp8u *pGFpBuff, Ipp8u *pGFpECBuff, Ipp8u *pDataBuff))
IPPAPI(fips_test_status, fips_selftest_ippsGFpECSharedSecretDH, (Ipp8u *pGFpBuff, Ipp8u *pGFpECBuff, Ipp8u *pDataBuff))

/* LMS */
IPPAPI(fips_test_status, fips_selftest_ippsLMSVerify_get_size, (int *pBufferSize))
IPPAPI(fips_test_status, fips_selftest_ippsLMSVerify, (Ipp8u *pDataBuff))

/*
// Enumerator that contains information about FIPS-approved
// functions inside the ippcp cryptographic boundary
*/
enum FIPS_IPPCP_FUNC {
  /* Approved functions, > 0 */
    AESEncryptCBC = 0x1,
    AESEncryptCBC_CS1,
    AESEncryptCBC_CS2,
    AESEncryptCBC_CS3,
    AESDecryptCBC,
    AESDecryptCBC_CS1,
    AESDecryptCBC_CS2,
    AESDecryptCBC_CS3,
    AESEncryptCFB,
    AESDecryptCFB,
    AESEncryptOFB,
    AESDecryptOFB,
    AESEncryptCTR,
    AESDecryptCTR,
    AES_CCMEncrypt,
    AES_CCMDecrypt,
    AES_CCMStart,
    AES_CCMGetTag,
    AES_GCMEncrypt,
    AES_GCMDecrypt,
    AES_GCMProcessIV,
    AES_GCMProcessAAD,
    AES_GCMStart,
    AES_GCMGetTag,
    RSASign_PKCS1v15_rmf,
    RSAVerify_PKCS1v15_rmf,
    RSASign_PSS_rmf,
    RSAVerify_PSS_rmf,
    RSA_GenerateKeys,
    GFpECSignDSA,
    GFpECVerifyDSA,
    GFpECSharedSecretDH,
    GFpECPublicKey,
    GFpECPrivateKey,
    HashUpdate_rmf,
    HashGetTag_rmf,
    HashFinal_rmf,
    HashMessage_rmf,
    AES_CMACUpdate,
    AES_CMACFinal,
    AES_CMACGetTag,
    HMACUpdate_rmf,
    HMACFinal_rmf,
    HMACGetTag_rmf,
    HMACMessage_rmf,
    RSAEncrypt_OAEP_rmf,
    RSADecrypt_OAEP_rmf,
    LMSVerify,

  /* Not approved functions or
   * FIPS-mode is not yet implemented, < 0
   */
    SMS4EncryptCBC = -0xFFF,
    SMS4EncryptCBC_CS1,
    SMS4EncryptCBC_CS2,
    SMS4EncryptCBC_CS3,
    SMS4DecryptCBC,
    SMS4DecryptCBC_CS1,
    SMS4DecryptCBC_CS2,
    SMS4DecryptCBC_CS3,
    SMS4EncryptCFB,
    SMS4DecryptCFB,
    SMS4EncryptOFB,
    SMS4DecryptOFB,
    SMS4EncryptCTR,
    SMS4DecryptCTR,
    SMS4_CCMStart,
    SMS4_CCMEncrypt,
    SMS4_CCMDecrypt,
    SMS4_CCMGetTag,
    /* XTS APIs didn't pass CAVP testing */
    AES_XTSEncrypt,
    AES_XTSDecrypt,
    AESEncryptXTS_Direct,
    AESDecryptXTS_Direct,
    MGF1_rmf,
    MGF2_rmf,
    AES_EncryptCFB16_MB,
    AES_S2V_CMAC,
    AES_SIVEncrypt,
    AES_SIVDecrypt,
    PRNGen,
    PRNGen_BN,
    PRNGenRDRAND,
    PRNGenRDRAND_BN,
    TRNGenRDSEED,
    TRNGenRDSEED_BN,
    PrimeGen,
    PrimeGen_BN,
    RSA_Encrypt,
    RSA_Decrypt,
    DLPGenKeyPair,
    DLPPublicKey,
    DLPSignDSA,
    DLPVerifyDSA,
    DLPSharedSecretDH,
    DLPGenerateDSA,
    DLPGenerateDH,
    GFpECVerify,
    GFpECSharedSecretDHC,
    GFpECSignNR,
    GFpECVerifyNR,
    GFpECSignSM2,
    GFpECVerifySM2,
    GFpECUserIDHashSM2,
    GFpECKeyExchangeSM2_SharedKey,
    GFpECEncryptSM2_Ext,
    GFpECDecryptSM2_Ext,
    GFpECESStart_SM2,
    GFpECESEncrypt_SM2,
    GFpECESDecrypt_SM2,
    GFpECESFinal_SM2,
    XMSSVerify
};

/**
 * \brief
 *
 *  An indicator if a function is FIPS-approved or not
 *
 * \param[in] function              member of FIPS_IPPCP_FUNC enumerator
 *                                  that corresponds to API being checked.
 * \return    func_fips_approved    equal to 1 if FIPS-approved algorithm is used
 *
 * Example:
 *          Library API             FIPS_IPPCP_FUNC
 *       ippsAESEncryptCBC    ->     AESEncryptCBC
 *       ippsGFpECSignDSA     ->     GFpECSignDSA
 *      ipps<functionality>   ->     <functionality>
 *
 */
IPPAPI(func_fips_approved, ippcp_is_fips_approved_func, (enum FIPS_IPPCP_FUNC function))

#if defined( __cplusplus )
}
#endif

#endif // IPPCP_FIPS_CERT_H
