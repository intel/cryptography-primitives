.. _sms4encryptecb:



SMS4EncryptECB
==============


Encrypts plaintext message by using ECB encryption mode (deprecated).


Syntax
------


IppStatus ippsSMS4EncryptECB(const Ipp8u \*pSrc, Ipp8u \*pDst, int len,
const IppsSMS4Spec\* pCtx);


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
     -  Length of the input plaintext data in bytes.
   * -     pCtx   
     -  Pointer to the IppsSMS4Spec context.




Description
-----------


.. note::


   The ECB functionality remains in the library, but it is not safe when
   used as is. Use any other mode, for example CBC.


The function encrypts the input data stream of a variable length
according to the cipher scheme specified in :term:`NIST SP 800-38A <[NIST SP 800-38A]>`.


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
     -  Indicates an error condition if len is not divisible by cipher block size.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



