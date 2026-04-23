.. _aes_gcmencrypt:


AES_GCMEncrypt
==============


Encrypts a data buffer in the GCM mode.


Syntax
------


IppStatus ippsAES_GCMEncrypt(const Ipp8u\* pSrc, Ipp8u\* pDst, int len,
IppsAES_GCMState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc
     - Pointer to the input plaintext data stream of a variable length.
   * - pDst
     - Pointer to the resulting ciphertext data stream.
   * - len
     - Length of the plaintext and ciphertext data stream in bytes.
   * - pState
     - Pointer to the IppsAES_GCMState context.




Description
-----------


The function encrypts the input data stream of a variable length
according to GCM as specified in :term:`NIST SP 800-38D <[NIST SP 800-38D]>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr
     - Indicates an error condition if the context parameter does not match the operation.
   * - ippStsLengthErr
     - Indicates an error condition if len is less than zero.



