.. _sms4decryptofb:


SMS4DecryptOFB
==============


Decrypts a variable length data stream using SMS4 block cipher in the
OFB mode.


Syntax
------


IppStatus ippsSMS4DecryptOFB (const Ipp8u\* pSrc, Ipp8u\* pDst, int len,
int ofbBlkSize, const IppsSMS4Spec\* pCtx, Ipp8u\* pIV);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrc    
     -  Pointer to the input ciphertext data stream of variable length.
   * -     pDst   
     -  Pointer to the resulting plaintext data stream.
   * -     len   
     -  Length of the ciphertext data stream in bytes.
   * -     ofbBlkSize    
     -  Size of the OFB block in bytes.
   * -     pCtx   
     -  Pointer to the IppsSMS4Spec context.
   * -     pIV    
     -  Pointer to the initialization vector for the OFB mode operation.




Description
-----------


The function decrypts the input data stream of a variable length in the
OFB mode as specified in :term:`NIST SP 800-38A <[NIST SP 800-38A]>`.


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
     -  Indicates an error condition if lenis not divisible by the ofbBlkSize parameter value.
   * -     ippStsOFBSizeErr    
     -  Indicates an error condition if the value of ofbBlkSize is illegal.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



