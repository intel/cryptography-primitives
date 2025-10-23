.. _appendix-b-deprecated-functions:


Deprecated Functions
====================


This appendix contains tables that list the deprecated Cryptography functions that are
targeted to be removed in future releases. If an application created with a previous
version calls a function listed here, then the source code must be modified.
The tables also specify the corresponding functions or workaround to replace the deprecated functions.

Deprecated since Intel® Cryptography Primitives Library 1.3.0
-------------------------------------------------------------

Deprecation related to preview features:

.. list-table::
   :header-rows: 1

   * - Functionality
     - Substitution or Workaround
   * - ippsLMSBufferGetSize
     - ippsLMSVerifyBufferGetSize

Deprecated since Intel® Cryptography Primitives Library 1.2.0
-------------------------------------------------------------

Deprecation related to preview features:

.. list-table::
   :header-rows: 1

   * - Functionality
     - Substitution or Workaround
   * - ippsXMSSBufferGetSize
     - ippsXMSSVerifyBufferGetSize

Deprecated since Intel® Cryptography Primitives Library 1.0.0
-------------------------------------------------------------

.. list-table::
   :header-rows: 1

   * - Service Functionality
     - Substitution or Workaround
   * - ippcpGetNumThreads; ippcpGetEnabledNumThreads; ippcpSetNumThreads;
     - N/A
   * - ippcpGetLibVersion
     - cryptoGetLibVersion

Deprecated since Intel® Integrated Performance Primitives Cryptography (Intel® IPP Cryptography) 2020 Update1
-------------------------------------------------------------------------------------------------------------

.. list-table::
   :header-rows: 1

   * - Hash Functionality
     - Substitution or Workaround
   * - ippsSHA1GetSize; ippsSHA224GetSize; ippsSHA256GetSize; ippsSHA384GetSize; ippsSHA512GetSize; ippsSM3GetSize; ippsMD5GetSize
     - ippsHashGetSize_rmf
   * - ippsSHA1Init; ippsSHA224Init; ippsSHA256Init; ippsSHA384Init; ippsSHA512Init; ippsSM3Init; ippsMD5Init
     - ippsHashInit_rmf [1]_
   * - ippsSHA1Duplicate; ippsSHA224Duplicate; ippsSHA256Duplicate; ippsSHA384Duplicate; ippsSHA512Duplicate; ippsSM3Duplicate; ippsMD5Duplicate
     - ippsHashDuplicate_rmf
   * - ippsSHA1Pack, ippsSHA1Unpack; ippsSHA224Pack, ippsSHA224Unpack; ippsSHA256Pack, ippsSHA256Unpack; ippsSHA384Pack, ippsSHA384Unpack; ippsSHA512Pack, ippsSHA512Unpack; ippsSM3Pack, ippsSM3Unpack; ippsMD5Pack, ippsMD5Unpack
     - ippsHashPack_rmf, ippsHashUnpack_rmf
   * - ippsSHA1Update, ippsSHA1GetTag, ippsSHA1Final; ippsSHA224Update, ippsSHA224GetTag, ippsSHA224Final; ippsSHA256Update, ippsSHA256GetTag, ippsSHA256Final; ippsSHA384Update, ippsSHA384GetTag, ippsSHA384Final; ippsSHA512Update, ippsSHA512GetTag, ippsSHA512Final; ippsSM3Update, ippsSM3GetTag, ippsSM3Final; ippsMD5Update, ippsMD5GetTag, ippsMD5Final
     - ippsHashUpdate_rmf, ippsHashGetTag_rmf, ippsHashFinal_rmf
   * - ippsSHA1MessageDigest; ippsSHA224MessageDigest; ippsSHA256MessageDigest; ippsSHA384MessageDigest; ippsSHA512MessageDigest; ippsSM3MessageDigest; ippsMD5MessageDigest
     - ippsHashMessage_rmf [1]_
   * - ippsHashGetSize
     - ippsHashGetSize_rmf
   * - ippsHashInit [2]_
     - ippsHashInit_rmf [1]_
   * - ippsHashDuplicate
     - ippsHashDuplicate_rmf
   * - ippsHashPack, ippsHashUnpack
     - ippsHashPack_rmf, ippsHashUnpack_rmf
   * - ippsHashUpdate, ippsHashGetTag, ippsHashFinal
     - ippsHashUpdate_rmf, ippsHashGetTag_rmf, ippsHashFinal_rmf
   * - ippsHashMessage [2]_
     - ippsHashMessage_rmf [1]_

.. list-table::
   :header-rows: 1

   * - Keyed HMAC Functionality
     - Substitution or Workaround
   * - ippsHMAC_GetSize
     - ippsHMAC_GetSize_rmf
   * - ippsHMAC_Init [2]_
     - ippsHMAC_Init_rmf [1]_
   * - ippsHMAC_Pack, ippsHMAC_Unack, ippsHMAC_Duplicate
     - ippsHMAC_Pack_rmf, ippsHMAC_Unpack_rmf, ippsHMAC_Duplicate_rmf
   * - ippsHMAC_Update, ippsHMAC_Final, ippsHMAC_GetTag
     - ippsHMAC_Update_rmf, ippsHMAC_Final_rmf, ippsHMAC_GetTag_rmf
   * - ippsHMAC_Message [2]_
     - ippsHMAC_Message_rmf [1]_


.. [1] To choose hash algorithm, specify IppsHashMethod parameter

.. [2] IppsHashAlgId parameter used in ippsHMAC_Init and in ippsHMAC_Message for choosing hash algorithm is deprecated (see Recommended replacement column for alternative in **IppsHashAlgId to IppsHashMethod Parameter Map** below)


.. list-table::
   :header-rows: 1

   * - MGF Functionality
     - Substitution or Workaround
   * - ippsHMAC_GetSize
     - ippsHMAC_GetSize_rmf


.. list-table::
   :header-rows: 1

   * - RSA Encryption and Signature Schemes
     - Substitution or Workaround
   * - ippsRSAEncrypt_OAEP, ippsRSADecrypt_OAEP
     - ippsRSAEncrypt_OAEP_rmf, ippsRSADecrypt_OAEP_rmf
   * - ippsRSASign_PSS, ippsRSAVerify_PSS
     - ippsRSASign_PSS_rmf, ippsRSAVerify_PSS_rmf
   * - ippsRSASign_PKCS1v15, ippsRSAVerify_PKCS1v15
     - ippsRSASign_PKCS1v15_rmf, ippsRSAVerify_PKCS1v15_rmf

.. list-table::
   :header-rows: 1

   * - Elliptic Curve Cryptography (ECC)
     - Substitution or Workaround
   * - ippsECCPGetSize; ippsECCPGetSizeStd128r1; ippsECCPGetSizeStd128r2; ippsECCPGetSizeStd192r1; ippsECCPGetSizeStd224r1; ippsECCPGetSizeStd256r1; ippsECCPGetSizeStd384r1; ippsECCPGetSizeStd521r1; ippsECCPGetSizeStdSM2
     - ippsGFpECGetSize
   * - ippsECCPInit; ippsECCPInitStd128r1; ippsECCPInitStd128r2; ippsECCPInitStd192r1; ippsECCPInitStd224r1; ippsECCPInitStd256r1; ippsECCPInitStd384r1; ippsECCPInitStd521r1; ippsECCPInitStdSM2
     - ippsGFpECInitStd (this functions provides both initialization and set up standard EC set of parameters)
   * - ippsECCPSet
     - ippsGFpECSet
   * - ippsECCPSetStd
     - ippsGFpECInitStd (this functions provides both initialization and set up standard EC set of parameters)
   * - ippsECCPSetStd128r1; ippsECCPSetStd128r2; ippsECCPSetStd192r1; ippsECCPSetStd224r1; ippsECCPSetStd256r1; ippsECCPSetStd384r1; ippsECCPSetStd521r1; ippsECCPSetStdSM2
     - ippsGFpECInitStd128r1; ippsGFpECInitStd128r2; ippsGFpECInitStd192r1; ippsGFpECInitStd224r1; ippsGFpECInitStd256r1; ippsGFpECInitStd384r1; ippsGFpECInitStd521r1; ippsGFpECInitStdSM2
   * - ippsECCPBindGxyTblStd192r1; ippsECCPBindGxyTblStd224r1; ippsECCPBindGxyTblStd256r1; ippsECCPBindGxyTblStd384r1; ippsECCPBindGxyTblStd521r1; ippsECCPBindGxyTblStdSM2
     - ippsGFpECBindGxyTblStd192r1; ippsGFpECBindGxyTblStd224r1; ippsGFpECBindGxyTblStd256r1; ippsGFpECBindGxyTblStd384r1; ippsGFpECBindGxyTblStd521r1; ippsGFpECBindGxyTblStdSM2
   * - ippsECCPGet; ippsECCPGetOrderBitSize; ippsECCPValidate; ippsECCPPointGetSize, ippsECCPPointInit; ippsECCPSetPointAtInfinity; ippsECCPSetPoint, ippsECCPGetPoint; ippsECCPCheckPoint; ippsECCPComparePoint; ippsECCPNegativePoint; ippsECCPAddPoint; ippsECCPMulPointScalar
     - ippsGFpECGet; ippsGFpECGetSubgroup; ippsGFpECVerify; ippsGFpECPointGetSize, ippsGFpECPointInit; ippsGFpECSetPointAtInfinity; ippsGFpECSetPointRegular, ippsGFpECGetPointRegular; ippsGFpECTstPoint; ippsGFpECCmpPoint; ippsGFpECNegPoint; ippsGFpECAddPoint; ippsGFpECMulPoint
   * - ippsECCPGenKeyPair; ippsECCPPublicKey; ippsECCPValidateKeyPair; ippsECCPSetKeyPair
     - ippsGFpECPrivateKey; ippsGFpECPublicKey; ippsGFpECTstKeyPair; N/A
   * - ippsECCPSharedSecretDH; ippsECCPSharedSecretDHC
     - ippsGFpECSharedSecretDH; ippsGFpECSharedSecretDHC
   * - ippsECCPSignDSA; ippsECCPVerifyDSA; ippsECCPSignNR; ippsECCPVerifyNR; ippsECCPSignSM2; ippsECCPVerifySM2
     - ippsGFpECSignDSA; ippsGFpECVerifyDSA; ippsGFpECSignNR; ippsGFpECVerifyNR; ippsGFpECSignSM2; ippsGFpECVerifySM2

**IppsHashAlgId to IppsHashMethod Parameter Map:**

.. list-table::
   :header-rows: 1

   * - Algorithm
     - IppsHashAlgId (deprecated)
     - IppsHashMethod (recommended)
     - Notes
   * - SHA1
     - ippsHashAlg_SHA1
     - 1.ippsHashMethod_SHA1; 2.ippsHashMethod_SHA1_NI; 3.ippsHashMethod_SHA1_TT
     - 1.Intel® Secure Hash Algorithm - New Instructions (Intel® SHA-NI) not supported; 2.Intel® SHA-NI only supported; 3.Automatic switch on Intel® SHA-NI, if possible (tick-tock)
   * - SHA224
     - ippsHashAlg_SHA224
     - 1.ippsHashMethod_SHA224; 2.ippsHashMethod_SHA224_NI; 3.ippsHashMethod_SHA224_TT
     - 1.Intel® SHA-NI not supported; 2.Intel® SHA-NI only supported; 3.Automatic switch on Intel® SHA-NI, if possible supported
   * - SHA256
     - ippsHashAlg_SHA256
     - 1.ippsHashMethod_SHA256; 2.ippsHashMethod_SHA256_NI; 3.ippsHashMethod_SHA256_TT
     - 1.Intel® SHA-NI not supported; 2.Intel® SHA-NI only supported; 3.Automatic switch on Intel® SHA-NI, if possible supported
   * - SHA384
     - ippsHashAlg_SHA384
     - 1.ippsHashMethod_SHA384; 2.ippsHashMethod_SHA384_NI; 3.ippsHashMethod_SHA384_TT
     - 1.Intel® SHA512 not supported; 2.Intel® SHA512 only supported; 3.Automatic switch on Intel® SHA512, if possible supported
   * - SHA512
     - ippsHashAgl_SHA512
     - 1.ippsHashMethod_SHA512; 2.ippsHashMethod_SHA512_NI; 3.ippsHashMethod_SHA512_TT
     - 1.Intel® SHA512 not supported; 2.Intel® SHA512 only supported; 3.Automatic switch on Intel® SHA512, if possible supported
   * - SM3
     - ippsHashAlg_SM3
     - 1.ippsHashMethod_SM3; 2.ippsHashMethod_SM3_NI; 3.ippsHashMethod_SM3_TT
     - 1.Intel® SM3 not supported; 2.Intel® SM3 only supported; 3.Automatic switch on Intel® SM3, if possible supported
   * - MD5
     - ippsHashAlg_MD5
     - ippsHashMethod_MD5
     - N/A
   * - SHA512-224
     - ippsHashAlg_SHA512_224
     - 1.ippsHashMethod_SHA512_224; 2.ippsHashMethod_SHA512_224_NI; 3.ippsHashMethod_SHA512_224_TT
     - 1.Intel® SHA512 not supported; 2.Intel® SHA512 only supported; 3.Automatic switch on Intel® SHA512, if possible supported
   * - SHA512-256
     - ippsHashAlg_SHA512_256
     - 1.ippsHashMethod_SHA512_256; 2.ippsHashMethod_SHA512_256_NI; 3.ippsHashMethod_SHA512_256_TT
     - 1.Intel® SHA512 not supported; 2.Intel® SHA512 only supported; 3.Automatic switch on Intel® SHA512, if possible supported


Deprecated since Intel® IPP Cryptography 9.0
--------------------------------------------

.. list-table::
   :header-rows: 1

   * - Functionality
     - Substitution or Workaround
   * - ippsARCFive128DecryptCBC
     - N/A
   * - ippsARCFive128DecryptCFB
     - N/A
   * - ippsARCFive128DecryptCTR
     - N/A
   * - ippsARCFive128DecryptECB
     - N/A
   * - ippsARCFive128DecryptOFB
     - N/A
   * - ippsARCFive128EncryptCBC
     - N/A
   * - ippsARCFive128EncryptCFB
     - N/A
   * - ippsARCFive128EncryptCTR
     - N/A
   * - ippsARCFive128EncryptECB
     - N/A
   * - ippsARCFive128EncryptOFB
     - N/A
   * - ippsARCFive128GetSize
     - N/A
   * - ippsARCFive128Init
     - N/A
   * - ippsARCFive128Pack
     - N/A
   * - ippsARCFive128Unpack
     - N/A
   * - ippsARCFive64DecryptCBC
     - N/A
   * - ippsARCFive64DecryptCFB
     - N/A
   * - ippsARCFive64DecryptCTR
     - N/A
   * - ippsARCFive64DecryptECB
     - N/A
   * - ippsARCFive64DecryptOFB
     - N/A
   * - ippsARCFive64EncryptCBC
     - N/A
   * - ippsARCFive64EncryptCFB
     - N/A
   * - ippsARCFive64EncryptCTR
     - N/A
   * - ippsARCFive64EncryptECB
     - N/A
   * - ippsARCFive64EncryptOFB
     - N/A
   * - ippsARCFive64GetSize
     - N/A
   * - ippsARCFive64Init
     - N/A
   * - ippsARCFive64Pack
     - N/A
   * - ippsARCFive64Unpack
     - N/A
   * - ippsCMACRijndael128Final
     - ippsAES_CMACFinal
   * - ippsCMACRijndael128GetSize
     - ippsAES_CMACGetSize
   * - ippsCMACRijndael128Init
     - ippsAES_CMACInit
   * - ippsCMACRijndael128MessageDigest
     - ippsAES_CMACGetTag
   * - ippsCMACRijndael128Update
     - ippsAES_CMACUpdate
   * - ippsCMACSafeRijndael128Init
     - ippsAES_CMACInit
   * - ippsDAARijndael128Final
     - N/A
   * - ippsDAARijndael128GetSize
     - N/A
   * - ippsDAARijndael128Init
     - N/A
   * - ippsDAARijndael128MessageDigest
     - N/A
   * - ippsDAARijndael128Update
     - N/A
   * - ippsDAARijndael192Final
     - N/A
   * - ippsDAARijndael192GetSize
     - N/A
   * - ippsDAARijndael192Init
     - N/A
   * - ippsDAARijndael192MessageDigest
     - N/A
   * - ippsDAARijndael192Update
     - N/A
   * - ippsDAARijndael256Final
     - N/A
   * - ippsDAARijndael256GetSize
     - N/A
   * - ippsDAARijndael256Init
     - N/A
   * - ippsDAARijndael256MessageDigest
     - N/A
   * - ippsDAARijndael256Update
     - N/A
   * - ippsDAASafeRijndael128Init
     - N/A
   * - ippsDAATDESFinal
     - N/A
   * - ippsDAATDESGetSize
     - N/A
   * - ippsDAATDESInit
     - N/A
   * - ippsDAATDESMessageDigest
     - N/A
   * - ippsDAATDESUpdate
     - N/A
   * - ippsECCBAddPoint
     - N/A
   * - ippsECCBCheckPoint
     - N/A
   * - ippsECCBComparePoint
     - N/A
   * - ippsECCBGenKeyPair
     - N/A
   * - ippsECCBGet
     - N/A
   * - ippsECCBGetOrderBitSize
     - N/A
   * - ippsECCBGetPoint
     - N/A
   * - ippsECCBGetSize
     - N/A
   * - ippsECCBInit
     - N/A
   * - ippsECCBMulPointScalar
     - N/A
   * - ippsECCBNegativePoint
     - N/A
   * - ippsECCBPointGetSize
     - N/A
   * - ippsECCBPointInit
     - N/A
   * - ippsECCBPublicKey
     - N/A
   * - ippsECCBSet
     - N/A
   * - ippsECCBSetKeyPair
     - N/A
   * - ippsECCBSetPoint
     - N/A
   * - ippsECCBSetPointAtInfinity
     - N/A
   * - ippsECCBSetStd
     - N/A
   * - ippsECCBSharedSecretDH
     - N/A
   * - ippsECCBSharedSecretDHC
     - N/A
   * - ippsECCBSignDSA
     - N/A
   * - ippsECCBSignNR
     - N/A
   * - ippsECCBValidate
     - N/A
   * - ippsECCBValidateKeyPair
     - N/A
   * - ippsECCBVerifyDSA
     - N/A
   * - ippsECCBVerifyNR
     - N/A
   * - ippsHMACMD5Duplicate
     - ippsHMAC_Duplicate
   * - ippsHMACMD5Final
     - ippsHMAC_Final
   * - ippsHMACMD5GetSize
     - ippsHMAC_GetSize
   * - ippsHMACMD5GetTag
     - ippsHMAC_GetTag
   * - ippsHMACMD5Init
     - ippsHMAC_Init
   * - ippsHMACMD5MessageDigest
     - ippsHMAC_Message
   * - ippsHMACMD5Pack
     - ippsHMAC_Pack
   * - ippsHMACMD5Unpack
     - ippsHMAC_Unpack
   * - ippsHMACMD5Update
     - ippsHMAC_Update
   * - ippsHMACSHA1Duplicate
     - ippsHMAC_Duplicate
   * - ippsHMACSHA1Final
     - ippsHMAC_Final
   * - ippsHMACSHA1GetSize
     - ippsHMAC_GetSize
   * - ippsHMACSHA1GetTag
     - ippsHMAC_GetTag
   * - ippsHMACSHA1Init
     - ippsHMAC_Init
   * - ippsHMACSHA1MessageDigest
     - ippsHMAC_Message
   * - ippsHMACSHA1Pack
     - ippsHMAC_Pack
   * - ippsHMACSHA1Unpack
     - ippsHMAC_Unpack
   * - ippsHMACSHA1Update
     - ippsHMAC_Update
   * - ippsHMACSHA224Duplicate
     - ippsHMAC_Duplicate
   * - ippsHMACSHA224Final
     - ippsHMAC_Final
   * - ippsHMACSHA224GetSize
     - ippsHMAC_GetSize
   * - ippsHMACSHA224GetTag
     - ippsHMAC_GetTag
   * - ippsHMACSHA224Init
     - ippsHMAC_Init
   * - ippsHMACSHA224MessageDigest
     - ippsHMAC_Message
   * - ippsHMACSHA224Pack
     - ippsHMAC_Pack
   * - ippsHMACSHA224Unpack
     - ippsHMAC_Unpack
   * - ippsHMACSHA224Update
     - ippsHMAC_Update
   * - ippsHMACSHA256Duplicate
     - ippsHMAC_Duplicate
   * - ippsHMACSHA256Final
     - ippsHMAC_Final
   * - ippsHMACSHA256GetSize
     - ippsHMAC_GetSize
   * - ippsHMACSHA256GetTag
     - ippsHMAC_GetTag
   * - ippsHMACSHA256Init
     - ippsHMAC_Init
   * - ippsHMACSHA256MessageDigest
     - ippsHMAC_Message
   * - ippsHMACSHA256Pack
     - ippsHMAC_Pack
   * - ippsHMACSHA256Unpack
     - ippsHMAC_Unpack
   * - ippsHMACSHA256Update
     - ippsHMAC_Update
   * - ippsHMACSHA384Duplicate
     - ippsHMAC_Duplicate
   * - ippsHMACSHA384Final
     - ippsHMAC_Final
   * - ippsHMACSHA384GetSize
     - ippsHMAC_GetSize
   * - ippsHMACSHA384GetTag
     - ippsHMAC_GetTag
   * - ippsHMACSHA384Init
     - ippsHMAC_Init
   * - ippsHMACSHA384MessageDigest
     - ippsHMAC_Message
   * - ippsHMACSHA384Pack
     - ippsHMAC_Pack
   * - ippsHMACSHA384Unpack
     - ippsHMAC_Unpack
   * - ippsHMACSHA384Update
     - ippsHMAC_Update
   * - ippsHMACSHA512Duplicate
     - ippsHMAC_Duplicate
   * - ippsHMACSHA512Final
     - ippsHMAC_Final
   * - ippsHMACSHA512GetSize
     - ippsHMAC_GetSize
   * - ippsHMACSHA512GetTag
     - ippsHMAC_GetTag
   * - ippsHMACSHA512Init
     - ippsHMAC_Init
   * - ippsHMACSHA512MessageDigest
     - ippsHMAC_Message
   * - ippsHMACSHA512Pack
     - ippsHMAC_Pack
   * - ippsHMACSHA512Unpack
     - ippsHMAC_Unpack
   * - ippsHMACSHA512Update
     - ippsHMAC_Update
   * - ippsMGF_MD5
     - ippsMGF
   * - ippsMGF_SHA1
     - ippsMGF
   * - ippsMGF_SHA224
     - ippsMGF
   * - ippsMGF_SHA256
     - ippsMGF
   * - ippsMGF_SHA384
     - ippsMGF
   * - ippsMGF_SHA512
     - ippsMGF
   * - ippsRSADecrypt
     - ippsRSA_Decrypt
   * - ippsRSAEncrypt
     - ippsRSA_Encrypt
   * - ippsRSAGenerate
     - ippsRSA_GenerateKeys
   * - ippsRSAGetKey
     - ippsRSA_GetPublicKey, ippsRSA_GetPrivateKeyType1, ippsRSA_GetPrivateKeyType2
   * - ippsRSAGetSize
     - ippsRSA_GetSizePublicKey
   * - ippsRSAInit
     - ippsRSA_InitPublicKey
   * - ippsRSAOAEPDecrypt
     - ippsRSADecrypt_OAEP
   * - ippsRSAOAEPDecrypt_MD5
     - ippsRSADecrypt_OAEP
   * - ippsRSAOAEPDecrypt_SHA1
     - ippsRSADecrypt_OAEP
   * - ippsRSAOAEPDecrypt_SHA224
     - ippsRSADecrypt_OAEP
   * - ippsRSAOAEPDecrypt_SHA256
     - ippsRSADecrypt_OAEP
   * - ippsRSAOAEPDecrypt_SHA384
     - ippsRSADecrypt_OAEP
   * - ippsRSAOAEPDecrypt_SHA512
     - ippsRSADecrypt_OAEP
   * - ippsRSAOAEPEncrypt
     - ippsRSAEncrypt_OAEP
   * - ippsRSAOAEPEncrypt_MD5
     - ippsRSAEncrypt_OAEP
   * - ippsRSAOAEPEncrypt_SHA1
     - ippsRSAEncrypt_OAEP
   * - ippsRSAOAEPEncrypt_SHA224
     - ippsRSAEncrypt_OAEP
   * - ippsRSAOAEPEncrypt_SHA256
     - ippsRSAEncrypt_OAEP
   * - ippsRSAOAEPEncrypt_SHA384
     - ippsRSAEncrypt_OAEP
   * - ippsRSAOAEPEncrypt_SHA512
     - ippsRSAEncrypt_OAEP
   * - ippsRSAPack
     - N/A
   * - ippsRSASSASign
     - ippsRSASign_PSS
   * - ippsRSASSASign_MD5
     - ippsRSASign_PSS
   * - ippsRSASSASign_MD5_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSASSASign_SHA1
     - ippsRSASign_PSS
   * - ippsRSASSASign_SHA1_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSASSASign_SHA224
     - ippsRSASign_PSS
   * - ippsRSASSASign_SHA224_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSASSASign_SHA256
     - ippsRSASign_PSS
   * - ippsRSASSASign_SHA256_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSASSASign_SHA384
     - ippsRSASign_PSS
   * - ippsRSASSASign_SHA384_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSASSASign_SHA512
     - ippsRSASign_PSS
   * - ippsRSASSASign_SHA512_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSASSAVerify
     - ippsRSAVerify_PSS
   * - ippsRSASSAVerify_MD5
     - ippsRSAVerify_PSS
   * - ippsRSASSAVerify_MD5_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSASSAVerify_SHA1
     - ippsRSAVerify_PSS
   * - ippsRSASSAVerify_SHA1_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSASSAVerify_SHA224
     - ippsRSAVerify_PSS
   * - ippsRSASSAVerify_SHA224_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSASSAVerify_SHA256
     - ippsRSAVerify_PSS
   * - ippsRSASSAVerify_SHA256_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSASSAVerify_SHA384
     - ippsRSAVerify_PSS
   * - ippsRSASSAVerify_SHA384_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSASSAVerify_SHA512
     - ippsRSAVerify_PSS
   * - ippsRSASSAVerify_SHA512_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSASSA_PKCS1v15_Sign
     - ippsRSASign_PKCS1v15
   * - ippsRSASSA_PKCS1v15_Verify
     - ippsRSAVerify_PKCS1v15
   * - ippsRSASSA_PSS_Sign
     - ippsRSASign_PSS
   * - ippsRSASSA_PSS_Verify
     - ippsRSAVerify_PSS
   * - ippsRSASetKey
     - ippsRSA_SetPublicKey, ippsRSA_SetPrivateKeyType1, ippsRSA_SetPrivateKeyType2
   * - ippsRSAUnpack
     - N/A
   * - ippsRSAValidate
     - ippsRSA_ValidateKeys
   * - ippsRSA_Decrypt_PKCSv15
     - ippsRSADecrypt_PKCSv15
   * - ippsRSA_Encrypt_PKCSv15
     - ippsRSAEncrypt_PKCSv15
   * - ippsRSA_OAEPDecrypt
     - ippsRSADecrypt_OAEP
   * - ippsRSA_OAEPDecrypt_MD5
     - ippsRSADecrypt_OAEP
   * - ippsRSA_OAEPDecrypt_SHA1
     - ippsRSADecrypt_OAEP
   * - ippsRSA_OAEPDecrypt_SHA224
     - ippsRSADecrypt_OAEP
   * - ippsRSA_OAEPDecrypt_SHA256
     - ippsRSADecrypt_OAEP
   * - ippsRSA_OAEPDecrypt_SHA384
     - ippsRSADecrypt_OAEP
   * - ippsRSA_OAEPDecrypt_SHA512
     - ippsRSADecrypt_OAEP
   * - ippsRSA_OAEPEncrypt
     - ippsRSAEncrypt_OAEP
   * - ippsRSA_OAEPEncrypt_MD5
     - ippsRSAEncrypt_OAEP
   * - ippsRSA_OAEPEncrypt_SHA1
     - ippsRSAEncrypt_OAEP
   * - ippsRSA_OAEPEncrypt_SHA224
     - ippsRSAEncrypt_OAEP
   * - ippsRSA_OAEPEncrypt_SHA256
     - ippsRSAEncrypt_OAEP
   * - ippsRSA_OAEPEncrypt_SHA384
     - ippsRSAEncrypt_OAEP
   * - ippsRSA_OAEPEncrypt_SHA512
     - ippsRSAEncrypt_OAEP
   * - ippsRSA_SSASign
     - ippsRSASign_PSS
   * - ippsRSA_SSASign_MD5
     - ippsRSASign_PSS
   * - ippsRSA_SSASign_MD5_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSA_SSASign_SHA1
     - ippsRSASign_PSS
   * - ippsRSA_SSASign_SHA1_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSA_SSASign_SHA224
     - ippsRSASign_PSS
   * - ippsRSA_SSASign_SHA224_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSA_SSASign_SHA256
     - ippsRSASign_PSS
   * - ippsRSA_SSASign_SHA256_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSA_SSASign_SHA384
     - ippsRSASign_PSS
   * - ippsRSA_SSASign_SHA384_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSA_SSASign_SHA512
     - ippsRSASign_PSS
   * - ippsRSA_SSASign_SHA512_PKCSv15
     - ippsRSASign_PKCS1v15
   * - ippsRSA_SSAVerify
     - ippsRSAVerify_PSS
   * - ippsRSA_SSAVerify_MD5
     - ippsRSAVerify_PSS
   * - ippsRSA_SSAVerify_MD5_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSA_SSAVerify_SHA1
     - ippsRSAVerify_PSS
   * - ippsRSA_SSAVerify_SHA1_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSA_SSAVerify_SHA224
     - ippsRSAVerify_PSS
   * - ippsRSA_SSAVerify_SHA224_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSA_SSAVerify_SHA256
     - ippsRSAVerify_PSS
   * - ippsRSA_SSAVerify_SHA256_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSA_SSAVerify_SHA384
     - ippsRSAVerify_PSS
   * - ippsRSA_SSAVerify_SHA384_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRSA_SSAVerify_SHA512
     - ippsRSAVerify_PSS
   * - ippsRSA_SSAVerify_SHA512_PKCSv15
     - ippsRSAVerify_PKCS1v15
   * - ippsRijndael128CCMDecrypt
     - ippsAES_CCMDecrypt
   * - ippsRijndael128CCMDecryptMessage
     - ippsAES_CCMDecrypt
   * - ippsRijndael128CCMEncrypt
     - ippsAES_CCMEncrypt
   * - ippsRijndael128CCMEncryptMessage
     - ippsAES_CCMEncrypt
   * - ippsRijndael128CCMGetSize
     - ippsAES_CCMGetSize
   * - ippsRijndael128CCMGetTag
     - ippsAES_CCMGetTag
   * - ippsRijndael128CCMInit
     - ippsAES_CCMInit
   * - ippsRijndael128CCMMessageLen
     - ippsAES_CCMMessageLen
   * - ippsRijndael128CCMStart
     - ippsAES_CCMStart
   * - ippsRijndael128CCMTagLen
     - ippsAES_CCMTagLen
   * - ippsRijndael128DecryptCBC
     - ippsAESDecryptCBC
   * - ippsRijndael128DecryptCFB
     - ippsAESDecryptCFB
   * - ippsRijndael128DecryptCTR
     - ippsAESDecryptCTR
   * - ippsRijndael128DecryptECB
     - ippsAESDecryptECB
   * - ippsRijndael128DecryptOFB
     - ippsAESDecryptOFB
   * - ippsRijndael128EncryptCBC
     - ippsAESEncryptCBC
   * - ippsRijndael128EncryptCFB
     - ippsAESEncryptCFB
   * - ippsRijndael128EncryptCTR
     - ippsAESEncryptCTR
   * - ippsRijndael128EncryptECB
     - ippsAESEncryptECB
   * - ippsRijndael128EncryptOFB
     - ippsAESEncryptOFB
   * - ippsRijndael128GCMDecrypt
     - ippsAES_GCMDecrypt
   * - ippsRijndael128GCMEncrypt
     - ippsAES_GCMEncrypt
   * - ippsRijndael128GCMGetSizeManaged
     - ippsAES_GCMGetSize
   * - ippsRijndael128GCMGetTag
     - ippsAES_GCMGetTag
   * - ippsRijndael128GCMInitManaged
     - ippsAES_GCMInit
   * - ippsRijndael128GCMProcessAAD
     - ippsAES_GCMProcessAAD
   * - ippsRijndael128GCMProcessIV
     - ippsAES_GCMProcessIV
   * - ippsRijndael128GCMReset
     - ippsAES_GCMReset
   * - ippsRijndael128GCMStart
     - ippsAES_GCMStart
   * - ippsRijndael128GetSize
     - ippsAESGetSize
   * - ippsRijndael128Init
     - ippsAESInit
   * - ippsRijndael128Pack
     - ippsAESPack
   * - ippsRijndael128SetKey
     - ippsAESSetKey
   * - ippsRijndael128Unpack
     - ippsAESUnpack
   * - ippsRijndael192DecryptCBC
     - ippsAESDecryptCBC
   * - ippsRijndael192DecryptCFB
     - ippsAESDecryptCFB
   * - ippsRijndael192DecryptCTR
     - ippsAESDecryptCTR
   * - ippsRijndael192DecryptECB
     - ippsAESDecryptECB
   * - ippsRijndael192DecryptOFB
     - ippsAESDecryptOFB
   * - ippsRijndael192EncryptCBC
     - ippsAESEncryptCBC
   * - ippsRijndael192EncryptCFB
     - ippsAESEncryptCFB
   * - ippsRijndael192EncryptCTR
     - ippsAESEncryptCTR
   * - ippsRijndael192EncryptECB
     - ippsAESEncryptECB
   * - ippsRijndael192EncryptOFB
     - ippsAESEncryptOFB
   * - ippsRijndael192GetSize
     - ippsAESGetSize
   * - ippsRijndael192Init
     - ippsAESInit
   * - ippsRijndael192Pack
     - ippsAESPack
   * - ippsRijndael192Unpack
     - ippsAESUnpack
   * - ippsRijndael256DecryptCBC
     - ippsAESDecryptCBC
   * - ippsRijndael256DecryptCFB
     - ippsAESDecryptOFB
   * - ippsRijndael256DecryptCTR
     - ippsAESDecryptCTR
   * - ippsRijndael256DecryptECB
     - ippsAESDecryptECB
   * - ippsRijndael256DecryptOFB
     - ippsAESDecryptCFB
   * - ippsRijndael256EncryptCBC
     - ippsAESEncryptCBC
   * - ippsRijndael256EncryptCFB
     - ippsAESEncryptOFB
   * - ippsRijndael256EncryptCTR
     - ippsAESEncryptCTR
   * - ippsRijndael256EncryptECB
     - ippsAESEncryptECB
   * - ippsRijndael256EncryptOFB
     - ippsAESEncryptCFB
   * - ippsRijndael256GetSize
     - ippsAESGetSize
   * - ippsRijndael256Init
     - ippsAESInit
   * - ippsRijndael256Pack
     - ippsAESPack
   * - ippsRijndael256Unpack
     - ippsAESUnpack
   * - ippsSafeRijndael128Init
     - ippsAESInit
   * - ippsXCBCRijndael128Final
     - N/A
   * - ippsXCBCRijndael128GetSize
     - N/A
   * - ippsXCBCRijndael128GetTag
     - N/A
   * - ippsXCBCRijndael128Init
     - N/A
   * - ippsXCBCRijndael128MessageTag
     - N/A
   * - ippsXCBCRijndael128Update
     - N/A
