.. _aes_xtsinit:


AES_XTSInit
===========


Initializes user-supplied memory as IppsAES_XTSSpec context for future
use.


Syntax
------


IppStatus ippsAES_XTSInit(const Ipp8u\* pKey, int keyLen, int duBitSize,
IppsAES_XTSSpec\* pCtx, int ctxSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pKey
     - Pointer to the secret key.
   * - keyLen
     - Length of the secret key in bits.
   * - duBitSize
     - Length of the Data Unit in bits.
   * - pCtx
     - Pointer to the buffer being initialized as IppsAES_XTSSpec context.
   * - ctxSize
     - Available size of the buffer being initialized.




Description
-----------


This function initializes the memory pointed by pCtx as IppsAES_XTSSpec.
In addition, the function uses the initialization variable and
additional authenticated data to provide all necessary key material for
both encryption and decryption operations.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if the pCtx pointer is NULL.
   * - ippStsLengthErr
     - Indicates an error condition if keyLen is not equal to 16×8×2 or 32×8×2.
   * - ippStsMemAllocError
     - Indicates an error condition if the allocated memory is insufficient for the operation.
   * - | ippStsBadArgErr 
       | **[Only in FIPS-compliance mode]**
     - Indicates an error condition if tweak key is equal to the data keys (Key1 == Key2).



