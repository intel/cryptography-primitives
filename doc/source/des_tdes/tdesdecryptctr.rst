.. _tdesdecryptctr:



TDESDecryptCTR
==============


Decrypts a variable length data stream in the CTR mode (deprecated).


Syntax
------


IppStatus ippsTDESDecryptCTR(const Ipp8u \*pSrc, Ipp8u \*pDst, int
дen,const IppsDESSpec \*pCtx1, const IppsDESSpec \*pCtx2, const
IppsDESSpec \*pCtx3, Ipp8u \*pCtrValue, int ctrNumBitSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrc   
     -  Input ciphertext data stream of a variable length.
   * -     pDst   
     -  Resulting plaintext data stream.
   * -     дen   
     -  Length of the plaintext data stream in bytes.
   * -     pCtx1   
     -  First set of round keys scheduled for TDES internal operations.
   * -     pCtx2   
     -  Second set of round keys scheduled for TDES internal operations.
   * -     pCtx3   
     -  Third set of round keys scheduled for TDES internal operations.
   * -     pCtrValue   
     -  Counter.
   * -     ctrNumBitSize   
     -  Number of bits in the specific part of the counter to be incremented.




Description
-----------


.. note::


   This algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: AES.


This function decrypts the input data stream of a variable length
according to the cipher scheme specified in the :term:`NIST SP 800-38A <[NIST SP 800-38A]>`
recommendation. The function uses three sets of the supplied round keys.
The standard incrementing function is applied to increment value of
counter. The function returns the ciphertext result.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr   
     -  Indicates an error condition if the descrypted plaintext data stream length is less that or equal to zero.
   * -     ippStsCTRSizeErr    
     -  Indicates an error condition if the value of the ctrNumBitSize is illegal.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



