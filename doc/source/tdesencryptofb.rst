.. _tdesencryptofb:



TDESEncryptOFB
==============


Encrypts a variable length data stream according to the TDES algorithm
in the OFB mode (deprecated).


Syntax
------


IppStatus ippsTDESEncryptOFB (const Ipp8u\* pSrc, Ipp8u\* pDst, int len,
int ofbBlkSize, const IppsDESSpec \*pCtx1, const IppsDESSpec \* pCtx2,
const IppsDESSpec \*pCtx3, Ipp8u\* pIV);


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
   * -     ofbBlkSize    
     -  Size of the OFB block in bytes.
   * -     pCtx1   
     -  First set of round keys scheduled for TDES internal operations.
   * -     pCtx2   
     -  Second set of round keys scheduled for TDES internal operations.
   * -     pCtx3   
     -  Third set of round keys scheduled for TDES internal operations.
   * -     pIV    
     -  Pointer to the initialization vector for the OFB mode operation.




Description
-----------


.. note::


   This algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: AES.


This function encrypts the input data stream of a variable length in the
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



