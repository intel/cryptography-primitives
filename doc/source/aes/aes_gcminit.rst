.. _aes_gcminit:


AES_GCMInit
===========


Initializes user-supplied memory as the IppsAES_GCMState context for
future use.


Syntax
------


IppStatus ippsAES_GCMInit(const Ipp8u\* pKey, int keyLen,
IppsAES_GCMState\* pState, int ctxSize);


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
     - Length of the secret key.
   * - pState
     - Pointer to the buffer being initialized as IppsAES_GCMState context.
   * - ctxSize
     - Available size of the buffer.




Description
-----------


The function initializes the memory pointed by pState as the
IppsAES_GCMState context. In addition, the function uses the
initialization variable and additional authenticated data to provide all
necessary key material for both encryption and decryption.


Call the :ref:`AES_GCMGetSize <aes_gcmgetsize>`
function prior to AES_GCMInit to determine the size of the buffer.


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
