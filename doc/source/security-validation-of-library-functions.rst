.. _security-validation-of-library-functions:



Security Validation of Library Functions
========================================


Most of Intel® Cryptography Primitives Library
functions use secret data, such as keys, directly. For
example, AES functions convert an input secret key into key schedule,
which is used by all the cipher modes. The secret data might leak when
code processes various secrets with the different executed instructions
sequences or memory access patterns.


The difference in code behavior can be observed, analyzed, and, as a
result, several bits or the whole secret can be determined. It means the
code does not match the constant execution time (CET) design.


To check that the library matches the CET design, a special PINCER (Pin
Certification) test suite is used. The PINCER test suite is based on
Intel's dynamic binary instrumentation tool - Pin (see
*https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html*)
and includes a set of tests, where each test is responsible for one
separate library function.


The PINCER test runs the validated library function several times with
different inputs and collects two kinds of traces:


-  IP (Instruction Pointer) trace, which contains executed instructions
   addresses
-  Memory access trace, which contains memory access addresses and
   read/write instructions


The function complies with the CET design if collected traces are
identical. Otherwise, it does not meet the CET requirements.


Currently, PINCER tests are running on 64-bit Linux architecture and
cover a limited list of library functions. The tables below present
library functions covered by PINCER tests and their validation status.


.. list-table:: AES functions
   :header-rows: 1

   * -     Function Name
     -     Status
   * -      ippsAESSetKey
     -     passed
   * -     ippsAES{Encrypt/Decrypt}ECB
     -     passed
   * -      ippsAES{Encrypt/Decrypt}CBC
     -     passed
   * -     ippsAES{Encrypt/Decrypt}CBC_SC1
     -     passed
   * -      ippsAES{Encrypt/Decrypt}CBC_SC2
     -     passed
   * -      ippsAES{Encrypt/Decrypt}CBC_SC3
     -     passed
   * -      ippsAES{Encrypt/Decrypt}CFB
     -     passed
   * -      ippsAES{Encrypt/Decrypt}OFB
     -     passed
   * -      ippsAES{Encrypt/Decrypt}CTR
     -     passed
   * -      ippsAES{Encrypt/Decrypt}XTS_Direct
     -     passed
   * -      ippsAES_XTS{Encrypt/Decrypt}
     -     passed
   * -      ippsAES_GCM{Start/Encrypt/Decrypt}
     -     passed
   * -      ippsAES_SIV{Encrypt/Decrypt}
     -     passed
   * -     ippsAES_S2V_CMAC
     -     passed
   * -      ippsAES_CCM{Encrypt/Decrypt}
     -     passed
   * -     ippsAES_CMAC{Update/Final}
     -     passed




.. list-table:: SMS4 functions
   :header-rows: 1

   * -     Function Name
     -     Status
   * -      ippsSMS4SetKey
     -     passed
   * -      ippsSMS4{Encrypt/Decrypt}ECB
     -     passed
   * -      ippsSMS4{Encrypt/Decrypt}CBC
     -     passed
   * -      ippsSMS4{Encrypt/Decrypt}CBC_SC1
     -     passed
   * -      ippsSMS4{Encrypt/Decrypt}CBC_SC2
     -     passed
   * -     ippsSMS4{Encrypt/Decrypt}CBC_SC3
     -     passed
   * -      ippsSMS4{Encrypt/Decrypt}CFB
     -     passed
   * -     ippsSMS4{Encrypt/Decrypt}OFB
     -     passed
   * -      ippsSMS4{Encrypt/Decrypt}CTR
     -     passed
   * -      ippsSMS4_CCM{Encrypt/Decrypt}
     -     passed




.. list-table:: HMAC functions
   :header-rows: 1

   * -     Function Name
     -     Status
   * -      ippsHMACInit_rmf
     -     passed




.. list-table:: RSA functions
   :header-rows: 1

   * -     Function Name
     -     Status
   * -      ippsRSA_Decrypt
     -     passed
   * -      ippsRSADecrypt_OAEP
     -     passed
   * -      ippsRSADecrypt_OAEP_rmf
     -     passed
   * -      ipsRSASign_PSS
     -     passed
   * -      ipsRSASign_PSS_rmf
     -     passed
   * -      ipsRSASign_PKCS1v15
     -     passed
   * -      ipsRSASign_PKCS1v15_rmf
     -     passed
   * -      ippsRSA_MB_Decrypt
     -     passed




.. list-table:: DLP functions
   :header-rows: 1

   * -     Function Name
     -     Status
   * -      ippsDLPPublicKey
     -     passed
   * -      ippsDLPSharedSecretDH
     -     passed
   * -      ippsDLPSignDSA
     -     passed




.. list-table:: GFp functions
   :header-rows: 1

   * -     Function Name
     -     Status
   * -      ippsGFpAdd
     -     passed
   * -      ippsGFpAdd_PE
     -     passed
   * -      ippsGFpMul
     -     passed
   * -      ippsGFpMul_PE
     -     passed
   * -     ippsGFpSub
     -     passed
   * -      ippsGFpSub_PE
     -     passed
   * -      ippsGFpConj
     -     passed
   * -      ippsGFpNeg
     -     passed
   * -     ippsGFpSqr
     -     passed
   * -     ippsGFpExp
     -     passed
   * -     ippsGFpMultiExp
     -     passed
   * -     ippsGFpSqrt
     -     failed
   * -     ippsGFpInv
     -     passed




.. list-table:: EC over GFp functions
   :header-rows: 1

   * -     Function Name
     -     Status
   * -     ippsGFpECAddPoint
     -     passed
   * -     ippsGFpECNegPoint
     -     passed
   * -     ippsGFpECMulPoint
     -     passed
   * -     ippsGFpECPublicKey
     -     passed
   * -     ippsGFpECSharedSecretDH{C}
     -     passed
   * -     ippsGFpECSignDSA
     -     passed
   * -     ippsGFpECSignNR
     -     passed
   * -     ippsGFpSignSM2
     -     passed
   * -     ippsGFpECES{Start/Final}_SM2
     -     passed
   * -     ippsGFpECES{Encrypr/Decrypt}_SM2
     -     passed



