.. _sms4init:

SMS4Init
========


Initializes user-supplied memory as IppsSMS4Spec context for future use.


Syntax
------


IppStatus ippsSMS4Init(const Ipp8u\* pKey, int keyLen, IppsSMS4Spec\*
pCtx, int ctxSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pKey   
     -  Pointer to the SMS4 key.
   * -     keyLen    
     -  Key byte stream length. Must equal 16.
   * -     pCtx   
     -  Pointer to the buffer being initialized as IppsSMS4Spec context.
   * -     ctxSize   
     -  Available size of the buffer being initialized.




Description
-----------


This function initializes the memory pointed by pCtx as IppsSMS4Spec.
The key is used to provide all necessary key material for both
encryption and decryption operations.


.. note::


   If the pKey pointer is NULL, the function initializes the context
   with the zero key, which can help you to clean up the actual secret
   before releasing the context.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if the pCtx pointer is NULL.
   * -     ippStsLengthErr   
     -  Returns an error condition if keyLen is not equal to 16.
   * -     ippStsMemAllocErr   
     -  Indicates an error condition if the allocated memory is insufficient for the operation.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



.. rubric:: Related Information

:ref:`data-security-considerations`
