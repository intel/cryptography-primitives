.. _aes_cmacinit:


AES_CMACInit
============


Initializes user-supplied memory as IppsAES_CMACState context for future
use.


Syntax
------


IppStatus ippsAES_CMACInit(const Ipp8u\* pKey, int keyLen,
IppsAES_CMACState\* pState, int ctxSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pKey   
     - Pointer to the AES key.
   * - keyLen   
     - Key bytestream length (in bytes) defined by the IppsAESKeyLength enumerator.
   * - pState   
     - Pointer to the memory buffer being initialized as IppsAES_CMACState context.
   * - ctxSize   
     - Available size of the buffer.




Description
-----------


This function initializes the memory at the address of pState as the
IppsAES_CMACState context. In addition, the function uses the key to
provide all necessary key material for both encryption and decryption
operations.


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
     - Indicates an error condition if the pState pointer is NULL.
   * - ippStsLengthErr   
     - Indicates an error condition if keyLen is not equal to 16, 24, or 32.
   * - ippStsMemAllocErr   
     - Indicates an error condition if the allocated memory is insufficient for the operation.


.. rubric:: Related Information

:ref:`data-security-considerations`


