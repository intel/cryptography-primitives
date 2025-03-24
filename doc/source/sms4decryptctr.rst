.. _sms4decryptctr:


SMS4DecryptCTR
==============


Decrypts a variable length data stream using SMS4 block cipher in the
CTR mode.


Syntax
------


IppStatus ippsSMS4DecryptCTR(const Ipp8u\* pSrc, Ipp8u\* pDst, int
len,const IppsAESSpec\* pCtx, Ipp8u\* pCtrValue, int ctrNumBitSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrc   
     -  Pointer to the input ciphertext data stream.
   * -     pDst   
     -  Pointer to the resulting plaintext data stream of a variable length.
   * -     len   
     -  Length of the plaintext data stream in bytes.
   * -     pCtx   
     -  Pointer to the IppsAESSpec context.
   * -     pCtrValue   
     -  Pointer to the counter data block.
   * -     ctrNumBitSize   
     -  Number of bits in the specific part of the counter to be incremented.




Description
-----------


The function decrypts the input data stream of a variable length
according to the CTR mode as specified in the :term:`NIST SP 800-38A <[NIST SP 800-38A]>`.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr   
     -  Indicates an error condition if the output data stream length is less than or equal to zero.
   * -     ippStsCTRSizeErr    
     -  Indicates an error condition if the value of the ctrNumBitSize is illegal.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



