.. _aesdecryptcfb:



AESDecryptCFB
=============


Decrypts byte data stream according to AES in CFB mode.


Syntax
------


IppStatus ippsAESDecryptCFB(const Ipp8u\* pSrc, Ipp8u\* pDst, int
srclen, int cfbBlkSize, const IppsAESSpec\* pCtx, const Ipp8u\* pIV);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc
     - Pointer to the input ciphertext data stream.
   * - pDst
     - Pointer to the resulting plaintext data stream of variable length.
   * - srclen
     - Length of the ciphertext data stream in bytes.
   * - cfbBlkSize
     - Size of the CFB block in bytes.
   * - pCtx
     - Pointer to the IppsAESSpec context.
   * - pIV
     - Pointer to the initialization vector for the CFB mode operation.




Description
-----------


The function decrypts the input data stream of variable length according
to the CFB mode as specified in :term:`NIST SP 800-38A <[NIST SP 800-38A]>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr
     - Indicates an error condition if the output data stream length is less than or equal to zero.
   * - ippStsCFBSizeErr
     - Indicates an error condition if the value for cfbBlkSize is illegal.
   * - ippStsContextMatchErr
     - Indicates an error condition if the context parameter does not match the operation.
   * - ippStsUnderRunErr
     - Indicates an error condition if srcLen is not divisible by cipher block size.



