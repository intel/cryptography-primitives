.. _aes_ccmdecrypt:

AES_CCMDecrypt
==============


Decrypts a data buffer in the CCM mode.


Syntax
------


IppStatus ippsAES_CCMDecrypt(const Ipp8u\* pSrc, Ipp8u\* pDst, int len,
IppsAES_CCMState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc
     - Pointer to the input ciphertext data stream of variable length.
   * - pDst
     - Pointer to the resulting plaintext data stream.
   * - len
     - Length of the plaintext and ciphertext data stream in bytes.
   * - pState
     - Pointer to the IppsAES_CCMState context.




Description
-----------


The function decrypts the input ciphered data stream of a variable
length in the CCM mode as specified in :term:`NIST SP 800-38C <[NIST SP 800-38C]>`.


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
     - Indicates an error condition if len is less than zero or the value that
       accumulates len parameters from previous calls to AES_CCMDecrypt with
       the current value of len exceeds the tag length specified in the
       previous call to :ref:`AES_CCMMessageLen <aes_ccmmessagelen>`.



