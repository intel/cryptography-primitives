.. _tdesdecryptecb:

TDESDecryptECB
==============


Decrypts variable length data stream in the ECB mode (deprecated).


Syntax
------


IppStatus ippsTDESDecryptECB(const Ipp8u \*pSrc, Ipp8u \*pDst, int
length, const IppsDESSpec \*pCtx1, const IppsDESSpec \*pCtx2, const
IppsDESSpec \* pCtx3, IppsCPPadding padding);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrc   
     -  Input ciphertext data stream of variable length.
   * -     pDst   
     -  Resulting plaintext data stream.
   * -     length   
     -  Input data stream length in bytes.
   * -     pCtx1   
     -  First set of round keys scheduled for TDES internal operations.
   * -     pCtx2   
     -  Second set of round keys scheduled for TDES internal operations.
   * -     pCtx3   
     -  Third set of round keys scheduled for TDES internal operations.
   * -     padding   
     -  IppsPaddingNONE padding scheme.




Description
-----------


.. note::


   This algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: AES.


This function decrypts the input data stream of a variable length
according to the cipher scheme specified in :term:`NIST SP 800-38A <[NIST SP 800-38A]>`. The
function uses three sets of supplied round keys in the ECB mode. The
function returns the ciphertext result and validates the final plaintext
block.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr   
     -  Indicates an error condition if the decrypted plaintext data stream length is less than or equal to zero.
   * -     ippStsUnderRunErr    
     -  Indicates an error condition if length is not divisible by cipher block size.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the pCtx1, pCtx2, or pCtx3 parameter does not match the operation.



