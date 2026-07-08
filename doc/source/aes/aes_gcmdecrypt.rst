.. _aes_gcmdecrypt:


AES_GCMDecrypt
==============


Decrypts a data buffer in the GCM mode.


Syntax
------


IppStatus ippsAES_GCMDecrypt(const Ipp8u\* pSrc, Ipp8u\* pDst, int len,
IppsAES_GCMState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc
     - Pointer to the input ciphertext data stream of a variable length.
   * - pDst
     - Pointer to the resulting plaintext data stream.
   * - len
     - Length of the plaintext and ciphertext data stream in bytes.
   * - pState
     - Pointer to the IppsAES_GCMState context.




Description
-----------


The function decrypts the input cipher data stream of a variable length
according to GCM as specified in :term:`NIST SP 800-38D <[NIST SP 800-38D]>`.

.. warning::
   The AES-GCM API is designed to support incremental streaming. Consequently, 
   ``ippsAES_GCMDecrypt`` outputs plaintext immediately for each processed chunk. 
   Authentication is deferred until the final tag is computed via 
   :ref:`ippsAES_GCMGetTag <aes_gcmgettag>`. It is the application's responsibility 
   to manage the lifecycle of the decrypted buffer: the plaintext must not be consumed 
   as authentic until the final tag comparison is successful, and the buffer must be 
   cleared by the application if authentication fails.


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



