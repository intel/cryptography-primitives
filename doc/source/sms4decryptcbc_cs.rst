.. _sms4decryptcbc_cs:


SMS4DecryptCBC_CS
=================


Decrypts plaintext in the CBC ciphertext stealing mode of the SMS4 block
cipher.


Syntax
------


IppStatus ippsSMS4DecryptCBC_CS1(const Ipp8u\* pSrc, Ipp8u\* pDst, int
len, const IppsSMS4Spec\* pCtx, const Ipp8u\* pIV);


IppStatus ippsSMS4DecryptCBC_CS2(const Ipp8u\* pSrc, Ipp8u\* pDst, int
len, const IppsSMS4Spec\* pCtx, const Ipp8u\* pIV);


IppStatus ippsSMS4DecryptCBC_CS3(const Ipp8u\* pSrc, Ipp8u\* pDst, int
len, const IppsSMS4Spec\* pCtx, const Ipp8u\* pIV);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrc   
     -  Pointer to the input ciphertext data of variable length.
   * -     pDst   
     -  Pointer to the resulting plaintext data.
   * -     len   
     -  Length of the input data length in bytes.
   * -     pCtx   
     -  Pointer to the IppsSMS4Spec context.
   * -     pIV   
     -  Pointer to the initialization vector for the CBC mode operation.




Description
-----------


These functions decrypt the input data stream according to the three
variants of the Cipher Block Chaining (CBC) mode with Ciphertext
Stealing (CS), as specified in :term:`NIST SP 800-38A A. <[NIST SP 800-38A A.]>`.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr   
     - * For SMS4DecryptCBC_CS1 and SMS4DecryptCBC_CS2, indicates an error condition if the input data length is less than the cipher block size.
       * For SMS4DecryptCBC_CS3, indicates an error condition if the input data length is less than or equal to the cipher block size.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



