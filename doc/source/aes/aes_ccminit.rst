.. _aes_ccminit:


AES_CCMInit
===========


Initializes user-supplied memory as the IppsAES_CCMState context for
future use.


Syntax
------


IppStatus ippsAES_CCMInit(const Ipp8u\* pKey, int keyLen,
IppsAES_CCMState\* pState, int ctxSize);


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
     - Pointer to the buffer being initialized as IppsAES_CCMState
       context.
   * - ctxSize
     - Size of the buffer being initialized.


Description
-----------


The function initializes the memory pointed by pState as the
IppsAES_CCMState context. In addition, the function uses the
initialization variable and additional authenticated data to provide all
necessary key material for both encryption and decryption.


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
     - Indicates an error condition an error condition if keyLen is not equal to 16, 24, or 32.
   * - ippStsMemAllocErr   
     - Indicates an error condition if the allocated memory is insufficient for the operation.


   
.. rubric:: Related Information

:ref:`data-security-considerations`
