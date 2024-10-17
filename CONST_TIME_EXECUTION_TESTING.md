# Scope of the Constant-time execution testing of Intel® Cryptography Primitives Library

- [General information](#general)
- [Scope for ippcp library](#ippcp)
- [Scope for crypto_mb library](#cryptomb)

## General information <div id = 'general'>
- Testing is conducted under Linux for 64-bit Intel® Cryptography Primitives Library built with the compilers listed in [Build](./BUILD.md).
- Tested platforms: m7, y8, l9, k0, k1 (see the supported platforms list [here](./OVERVIEW.md#target-optimization-codes-in-function-names)).
- Testing scope described below is guaranteed to pass for **`release`** branches. This is not guaranteed for the **`develop`** branch ([branches description](./OVERVIEW.md#branches-description))
- Information about Pin-Based Constant Execution Checker can be found [here](https://github.com/intel/pin_based_cec)

## ippcp library <div id = 'ippcp'>
|     Tested Function      |                                         Parameters                                         |
| :----------------------: | :----------------------------------------------------------------------------------------: |
|    ippsAESEncryptCBC     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAESDecryptCBC     |                        Different key length:<br>128, 192, 256 bits                         |
|  ippsAESEncryptCBC_CS1   |                        Different key length:<br>128, 192, 256 bits                         |
|  ippsAESDecryptCBC_CS1   |                        Different key length:<br>128, 192, 256 bits                         |
|  ippsAESEncryptCBC_CS2   |                        Different key length:<br>128, 192, 256 bits                         |
|  ippsAESDecryptCBC_CS2   |                        Different key length:<br>128, 192, 256 bits                         |
|  ippsAESEncryptCBC_CS3   |                        Different key length:<br>128, 192, 256 bits                         |
|  ippsAESDecryptCBC_CS3   |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAES_CCMEncrypt    |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAES_CCMDecrypt    |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAESEncryptCFB     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAESDecryptCFB     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAES_CMACUpdate    |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAES_CMACFinal     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAESEncryptCTR     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAESDecryptCTR     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAESEncryptECB     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAESDecryptECB     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAES_GCMEncrypt    |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAES_GCMDecrypt    |                        Different key length:<br>128, 192, 256 bits                         |
|     ippsAES_GCMStart     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAESEncryptOFB     |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAESDecryptOFB     |                        Different key length:<br>128, 192, 256 bits                         |
|     ippsAES_S2V_CMAC     |                        Different key length:<br>128, 192, 256 bits                         |
|      ippsAESSetKey       |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAES_SIVEncrypt    |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAES_SIVDecrypt    |                        Different key length:<br>128, 192, 256 bits                         |
|    ippsAES_XTSEncrypt    |                           Different key length:<br>256, 512 bits                           |
|    ippsAES_XTSDecrypt    |                           Different key length:<br>256, 512 bits                           |
| ippsAESEncryptXTS_Direct |                           Different key length:<br>256, 512 bits                           |
| ippsAESDecryptXTS_Direct |                           Different key length:<br>256, 512 bits                           |
|        ippsCmp_BN        |                                             -                                              |
|     ippsDLPPublicKey     |                                             -                                              |
|  ippsDLPSharedSecretDH   |                                             -                                              |
|        ippsGFpAdd        |                                             -                                              |
|      ippsGFpAdd_PE       |                                             -                                              |
|       ippsGFpConj        |                                             -                                              |
|    ippsGFpECAddPoint     |                        Different curves:<br>p256r1, p384r1, p521r1                         |
|    ippsGFpECMulPoint     |                        Different curves:<br>p224r1, p256r1, p384r1                         |
|    ippsGFpECNegPoint     |                        Different curves:<br>p256r1, p384r1, p521r1                         |
|    ippsGFpECPublicKey    |                        Different curves:<br>p256r1, p384r1, p521r1                         |
| ippsGFpECSharedSecretDH  |                        Different curves:<br>p256r1, p384r1, p521r1                         |
| ippsGFpECSharedSecretDHC |                        Different curves:<br>p256r1, p384r1, p521r1                         |
|     ippsGFpECSignDSA     |                            Different curves:<br>p256r1, p384r1                             |
|     ippsGFpECSignNR      |                            Different curves:<br>p256r1, p384r1                             |
|     ippsGFpECSignSM2     |                                             -                                              |
|   ippsGFpECESStart_SM2   |                                             -                                              |
|  ippsGFpECESEncrypt_SM2  |                                             -                                              |
|  ippsGFpECESDecrypt_SM2  |                                             -                                              |
|   ippsGFpECESFinal_SM2   |                                             -                                              |
|        ippsGFpExp        |                                             -                                              |
|        ippsGFpInv        |                                             -                                              |
|        ippsGFpMul        |                                             -                                              |
|      ippsGFpMul_PE       |                                             -                                              |
|     ippsGFpMultiExp      |                                             -                                              |
|        ippsGFpNeg        |                                             -                                              |
|        ippsGFpSqr        |                                             -                                              |
|        ippsGFpSub        |                                             -                                              |
|      ippsGFpSub_PE       |                                             -                                              |
|     ippsHMACInit_rmf     | Different hashes:<br>sha1, sha256, sha224, sha384, sha512, <br>sha512-256, sha512-224, sm3 |
|     ippsRSA_Decrypt      |    Different key types and key length:<br>key type 1, 512 bits<br>key type 2, 512 bits     |
|   ippsRSADecrypt_OAEP    |    Different key types and key length:<br>key type 1, 512 bits<br>key type 2, 512 bits     |
| ippsRSADecrypt_OAEP_rmf  |    Different key types and key length:<br>key type 1, 512 bits<br>key type 2, 512 bits     |
|   ippsRSASign_PKCS1v15   |    Different key types and key length:<br>key type 1, 512 bits<br>key type 2, 512 bits     |
| ippsRSASign_PKCS1v15_rmf |    Different key types and key length:<br>key type 1, 512 bits<br>key type 2, 512 bits     |
|     ippsRSASign_PSS      |    Different key types and key length:<br>key type 1, 512 bits<br>key type 2, 512 bits     |
|   ippsRSASign_PSS_rmf    |    Different key types and key length:<br>key type 1, 512 bits<br>key type 2, 512 bits     |
|    ippsSMS4EncryptCBC    |                                             -                                              |
|    ippsSMS4DecryptCBC    |                                             -                                              |
|  ippsSMS4EncryptCBC_CS1  |                                             -                                              |
|  ippsSMS4DecryptCBC_CS1  |                                             -                                              |
|  ippsSMS4EncryptCBC_CS2  |                                             -                                              |
|  ippsSMS4DecryptCBC_CS2  |                                             -                                              |
|  ippsSMS4EncryptCBC_CS3  |                                             -                                              |
|  ippsSMS4DecryptCBC_CS3  |                                             -                                              |
|   ippsSMS4_CCMEncrypt    |                                             -                                              |
|   ippsSMS4_CCMDecrypt    |                                             -                                              |
|    ippsSMS4EncryptCFB    |                                             -                                              |
|    ippsSMS4DecryptCFB    |                                             -                                              |
|    ippsSMS4EncryptCTR    |                                             -                                              |
|    ippsSMS4DecryptCTR    |                                             -                                              |
|    ippsSMS4EncryptECB    |                                             -                                              |
|    ippsSMS4DecryptECB    |                                             -                                              |
|    ippsSMS4EncryptOFB    |                                             -                                              |
|    ippsSMS4DecryptOFB    |                                             -                                              |
|      ippsSMS4SetKey      |                                             -                                              |

## crypto_mb library <div id = 'cryptomb'>
|                 Function                 |                      Parameters                       |
| :--------------------------------------: | :---------------------------------------------------: |
|      mbx_nistp256_ecpublic_key_mb8       |     projective coordinates<br>affine coordinates      |
|      mbx_nistp384_ecpublic_key_mb8       |     projective coordinates<br>affine coordinates      |
|      mbx_nistp521_ecpublic_key_mb8       |     projective coordinates<br>affine coordinates      |
|         mbx_sm2_ecpublic_key_mb8         |     projective coordinates<br>affine coordinates      |
|          mbx_nistp256_ecdh_mb8           |     projective coordinates<br>affine coordinates      |
|          mbx_nistp384_ecdh_mb8           |     projective coordinates<br>affine coordinates      |
|          mbx_nistp521_ecdh_mb8           |     projective coordinates<br>affine coordinates      |
|       mbx_nistp256_ecdsa_sign_mb8        |                           -                           |
|       mbx_nistp384_ecdsa_sign_mb8        |                           -                           |
|       mbx_nistp521_ecdsa_sign_mb8        |                           -                           |
|    mbx_nistp256_ecdsa_sign_setup_mb8     |                           -                           |
|    mbx_nistp384_ecdsa_sign_setup_mb8     |                           -                           |
|    mbx_nistp521_ecdsa_sign_setup_mb8     |                           -                           |
|   mbx_nistp256_ecdsa_sign_complete_mb8   |                           -                           |
|   mbx_nistp384_ecdsa_sign_complete_mb8   |                           -                           |
|   mbx_nistp521_ecdsa_sign_complete_mb8   |                           -                           |
|    mbx_nistp256_ecpublic_key_ssl_mb8     |     projective coordinates<br>affine coordinates      |
|    mbx_nistp384_ecpublic_key_ssl_mb8     |     projective coordinates<br>affine coordinates      |
|    mbx_nistp521_ecpublic_key_ssl_mb8     |     projective coordinates<br>affine coordinates      |
|       mbx_sm2_ecpublic_key_ssl_mb8       |     projective coordinates<br>affine coordinates      |
|        mbx_nistp256_ecdh_ssl_mb8         |     projective coordinates<br>affine coordinates      |
|        mbx_nistp384_ecdh_ssl_mb8         |     projective coordinates<br>affine coordinates      |
|        mbx_nistp521_ecdh_ssl_mb8         |     projective coordinates<br>affine coordinates      |
|     mbx_nistp256_ecdsa_sign_ssl_mb8      |                           -                           |
|     mbx_nistp384_ecdsa_sign_ssl_mb8      |                           -                           |
|     mbx_nistp521_ecdsa_sign_ssl_mb8      |                           -                           |
|  mbx_nistp256_ecdsa_sign_setup_ssl_mb8   |                           -                           |
|  mbx_nistp384_ecdsa_sign_setup_ssl_mb8   |                           -                           |
|  mbx_nistp521_ecdsa_sign_setup_ssl_mb8   |                           -                           |
| mbx_nistp256_ecdsa_sign_complete_ssl_mb8 |                           -                           |
| mbx_nistp384_ecdsa_sign_complete_ssl_mb8 |                           -                           |
| mbx_nistp521_ecdsa_sign_complete_ssl_mb8 |                           -                           |
|        mbx_ed25519_public_key_mb8        |                           -                           |
|           mbx_ed25519_sign_mb8           |                           -                           |
|           mbx_rsa_private_mb8            | Different key length: <br>1024, 2048, 3072, 4096 bits |
|         mbx_rsa_private_crt_mb8          | Different key length: <br>1024, 2048, 3072, 4096 bits |
|         mbx_rsa_private_ssl_mb8          | Different key length: <br>1024, 2048, 3072, 4096 bits |
|       mbx_rsa_private_crt_ssl_mb8        | Different key length: <br>1024, 2048, 3072, 4096 bits |
|          mbx_sm2_ecdsa_sign_mb8          |                           -                           |
|        mbx_sm2_ecdsa_sign_ssl_mb8        |                           -                           |
|         mbx_sm4_encrypt_ecb_mb16         |                           -                           |
|         mbx_sm4_decrypt_ecb_mb16         |                           -                           |
|         mbx_sm4_encrypt_cbc_mb16         |                           -                           |
|         mbx_sm4_decrypt_cbc_mb16         |                           -                           |
|       mbx_sm4_encrypt_ctr128_mb16        |                           -                           |
|         mbx_sm4_encrypt_ofb_mb16         |                           -                           |
|       mbx_sm4_encrypt_cfb128_mb16        |                           -                           |
|       mbx_sm4_decrypt_cfb128_mb16        |                           -                           |
|       mbx_sm4_xts_encrypt_mb16           |                           -                           |
|       mbx_sm4_xts_decrypt_mb16           |                           -                           |
|       mbx_sm4_ccm_init_mb16              |                           -                           |
|       mbx_sm4_ccm_update_aad_mb16        |                           -                           |
|       mbx_sm4_ccm_encrypt_mb16           |                           -                           |
|       mbx_sm4_ccm_decrypt_mb16           |                           -                           |
|       mbx_sm4_ccm_get_tag_mb16           |                           -                           |
|       mbx_sm4_gcm_init_mb16              |                           -                           |
|       mbx_sm4_gcm_update_iv_mb16         |                           -                           |
|       mbx_sm4_gcm_update_aad_mb16        |                           -                           |
|       mbx_sm4_gcm_encrypt_mb16           |                           -                           |
|       mbx_sm4_gcm_decrypt_mb16           |                           -                           |
|       mbx_sm4_gcm_get_tag_mb16           |                           -                           |
|        mbx_x25519_public_key_mb8         |                           -                           |
|              mbx_x25519_mb8              |                           -                           |
