.. _aesdecryptecb:


AESDecryptECB
=============


Decrypts byte data stream by using the AES algorithm in the ECB mode
(deprecated).


Syntax
------


IppStatus ippsAESDecryptECB(const Ipp8u\* pSrc, Ipp8u\* pDst, int
srclen, const IppsAESSpec\* pCtx);


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
     - Pointer to the resulting plaintext data stream of variable length.
   * - srclen
     - Length of the ciphertext data stream in bytes.
   * - pCtx
     - Pointer to the IppsAESSpec context.




Description
-----------


.. note::


   The ECB functionality remains in the library, but it is not safe when
   used as is. Use any other mode, for example CBC.


The function decrypts the input data stream of a variable length
according to the ECB mode as specified in
:term:`NIST SP 800-38A <[NIST SP 800-38A]>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr
     - Indicates an error condition if the output data stream length is less than or equal to zero.
   * - ippStsContextMatchErr
     - Indicates an error condition if the context parameter does not match the operation.
   * - ippStsUnderRunErr
     - Indicates an error condition if srclen is not divisible by cipher block size.



