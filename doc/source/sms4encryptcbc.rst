.. _sms4encryptcbc:



SMS4EncryptCBC
==============


Encrypts byte data stream according to SMS4 in the CBC mode.


Syntax
------


IppStatus ippsSMS4EncryptCBC(const Ipp8u\* pSrc, Ipp8u\* pDst, int len,
const IppsSMS4Spec\* pCtx, const Ipp8u\* pIV);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrc   
     -  Pointer to the input plaintext data stream of variable length.
   * -     pDst   
     -  Pointer to the resulting ciphertext data stream.
   * -     len   
     -  Length of the plaintext data stream length in bytes.
   * -     pCtx   
     -  Pointer to the IppsSMS4Spec context.
   * -     pIV   
     -  Pointer to the initialization vector for the CBC mode operation.




Description
-----------


The function encrypts the input data stream of a variable length
according to the CBC mode as specified in :term:`NIST SP 800-38A <[NIST SP 800-38A]>`.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr   
     -  Indicates an error condition if the input data stream length is less than or equal to zero.
   * -     ippStsUnderRunErr   
     -  Indicates an error condition if len is not divisible by data block size.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



