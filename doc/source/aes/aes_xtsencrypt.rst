.. _aes_xtsencrypt:


AES_XTSEncrypt
==============


Encrypts a data buffer in the XTS mode.


Syntax
------


IppStatus ippsAES_XTSEncrypt(const Ipp8u\* pSrc, Ipp8u\* pDst, int
bitSizeLen, const IppsAES_XTSSpec\* pCtx, const Ipp8u\* pTweak, int
startCipherBlkNo);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc
     - Pointer to the input plaintext data stream of variable length.
   * - pDst
     - Pointer to the resulting ciphertext data stream.
   * - bitSizeLen
     - Length of the input buffer in bits.
   * - pCtx
     - Pointer to the IppsAES_XTSSpec context.
   * - pTweak
     - Pointer to the tweak vector assigned to the data unit being encrypted.
   * - startCipherBlkNo
     - Number of the first block of the data unit.




Description
-----------


The function encrypts the input data stream of a variable length in the
XTS mode as specified in :term:`IEEE P1619 <[IEEE P1619]>` and
:term:`NIST SP 800-38E <[NIST SP 800-38E]>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr
     - Indicates an error condition if the bitSizeLen parameter value is less than 128.
   * - ippStsBadArgErr
     - Indicates an error condition in the following cases:

       * ``startCipherBlkNo`` value is less than zero.
       * ``startCipherBlkNo`` value is greater than or equal to the number of the data unit blocks.
       * ``startCipherBlkNo×128+bitSizeLen`` value is greater than size of the data unit in bits.
       * size of the data unit in bits modulo 128 is zero and the ``bitSizeLen`` value modulo 128 is not zero.
       * ``bitSizeLen`` value modulo 128 is zero and
         startCipherBlkNo×128+bitSizeLen value is not equal to size of the data unit in bits.

   * - ippStsContextMatchErr
     - Indicates an error condition if the context parameter does not match the operation.



