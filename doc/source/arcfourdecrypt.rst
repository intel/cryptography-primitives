.. _arcfourdecrypt:

ARCFourDecrypt
==============


Decrypts a variable length data stream according to ARCFour
(deprecated).


Syntax
------


IppStatus ippsARCFourDecrypt(const Ipp8u\* pSrc, Ipp8u\* pDst, int
srclen, IppsARCFourState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pSrc   
     - Pointer to the input ciphertext data stream of variable length.
   * - pDst   
     - Pointer to the resulting plaintext data stream.
   * - srclen   
     - Length of the ciphertext data stream in octets.
   * - pCtx   
     - Pointer to the ARCFourState context.




Description
-----------


.. note::


   This function is deprecated.


The function decrypts the input data stream of a variable length
according to the ARCFour algorithm.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr   
     - Indicates an error condition if length of the input data stream is less than one octet.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the context parameter does not match the operation.



