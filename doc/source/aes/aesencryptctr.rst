.. _aesencryptctr:

AESEncryptCTR
=============


Encrypts a variable length data stream in the CTR mode.


Syntax
------


IppStatus ippsAESEncryptCTR(const Ipp8u\* pSrc, Ipp8u\* pDst, int
srcLen,const IppsAESSpec\* pCtx, Ipp8u\* pCtrValue , int ctrNumBitSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc
     - Pointer to the input plaintext data stream of a variable length.
   * - pDst
     - Pointer to the resulting ciphertext data stream.
   * - srcLen
     - Length of the plaintext data stream in bytes.
   * - pCtx
     - Pointer to the IppsAESSpec context.
   * - pCtrValue
     - Pointer to the counter data block.
   * - ctrNumBitSize
     - Number of bits in the specific part of the counter to be incremented.




Description
-----------


The function encrypts the input data stream of a variable length
according to the CTR mode as specified in
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
     - Indicates an error condition if the input data stream length is less than or equal to zero.
   * - ippStsCTRSizeErr
     - Indicates an error condition if the value of the ctrNumBitSize is illegal.
   * - ippStsContextMatchErr
     - Indicates an error condition if the context parameter does not match the operation.



