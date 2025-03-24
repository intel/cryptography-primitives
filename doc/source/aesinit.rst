.. _aesinit:

AESInit
=======


Initializes user-supplied memory as IppsAESSpec context for future use.


Syntax
------


IppStatus ippsAESInit(const Ipp8u\* pKey, int keylen, IppsAESSpec\*
pCtx, int ctxSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pKey   
     - Pointer to the AES key.
   * - keylen    
     - Key byte stream length in bytes defined by the IppsRijndaelKeyLength enumerator.
   * - pCtx   
     - Pointer to the buffer being initialized as IppsAESSpec context.
   * - ctxSize   
     - Available size of the buffer being initialized.




Description
-----------


This function initializes the memory pointed by pCtx as IppsAESSpec. The
key is used to provide all necessary key material for both encryption
and decryption operations.


.. note::


   If the pKey pointer is NULL, the function initializes the context
   with the zero key, which can help you to clean up the actual secret
   before releasing the context.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if the pCtx pointer is NULL.
   * - ippStsLengthErr   
     - Returns an error condition if keyLen is not equal to 16, 24, or 32.
   * - ippStsMemAllocErr   
     - Indicates an error condition if the allocated memory is insufficient for the operation.



