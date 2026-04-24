.. _sms4encryptcfb:


SMS4EncryptCFB
==============


Encrypts byte data stream using SMS4 block cipher in the CFB mode.


Syntax
------


IppStatus ippsSMS4EncryptCFB(const Ipp8u\* pSrc, Ipp8u\* pDst, int len,
int cfbBlkSize, const IppsSMS4Spec\* pCtx, const Ipp8u \*pIV);


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
     -  Length of the plaintext data stream in bytes.
   * -     cfbBlkSize    
     -  Size of the CFB block in bytes.
   * -     pCtx   
     -  Pointer to the IppsSMS4Spec context.
   * -     pIV   
     -  Pointer to the initialization vector for the CFB mode operation.




Description
-----------


The function encrypts the input data stream of variable length according
to the CFB mode as specified in :term:`NIST SP 800-38A <[NIST SP 800-38A]>`.


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
     -  Indicates an error condition if lenis not divisible by cfbBlkSize parameter value.
   * -     ippStsCFBSizeErr    
     -  Indicates an error condition if the value for cfbBlkSize is illegal.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



