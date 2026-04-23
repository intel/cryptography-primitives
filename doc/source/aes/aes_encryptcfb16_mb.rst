.. _aes_encryptcfb16_mb:


AES_EncryptCFB16_MB
===================


Encrypts multiple independent buffers of byte data according to AES in
the CFB mode with 16-byte CFB block size.


Syntax
------


IppStatus ippsAES_EncryptCFB16_MB(const Ipp8u\* pSrc[], Ipp8u\* pDst[],
int len[], const IppsAESSpec\* pCtx[], const Ipp8u \*pIV[], IppStatus
status[] , int numBuffers);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc[]
     - Pointer to the array of the input plaintext data streams of variable length.
   * - pDst[]
     - Pointer to the array of the resulting ciphertext data streams.
   * - len[]
     - Pointer to the array of the lengths of the plaintext data streams, in bytes.
   * - pCtx[]
     - Pointer to the array of the IppsAESSpec contexts.
   * - pIV[]
     - Pointer to the array of initialization vectors for the CFB mode operation.
   * - status[]
     - Pointer to the IppStatus array that contains the status for each processed buffer in an encryption operation.
   * - numBuffers
     - Number of buffers to be processed.




Description
-----------


The function performs the AES multi-buffer encryption operation, which
consists of several AES operations performed simultaneously with a
variable-length input data stream in accordance with the CFB mode, as
specified in :term:`NIST SP 800-38A <[NIST SP 800-38A]>`.


The function can perform a variable number of independent AES CFB
encryption operations at the same time. This number is specified in the
numBuffers parameter.


Each AES CFB encryption operation requires valid parameters that follow
the AESEncryptCFB syntax.


After execution, the statuses array contains statuses for each single
AES CFB encryption operation returned by AESEncryptCFB.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   All IppAESSpecs in operation must be initialized with the same size
   of key (see :ref:`ippsAESInit <aesinit>`
   and :ref:`ippsAESSetKey <aessetkey>`).


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr
     - Indicates an error condition if the input numBuffers parameter is less than or equal to zero.
   * - ippStsContextMatchErr
     - Indicates an error condition if input buffers have different key sizes.
   * - ippStsErr
     - Indicates an error when one or more processed operations are executed with errors. For details, check the statuses array.



