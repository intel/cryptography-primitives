.. _sms4setkey:


SMS4SetKey
==========


Resets the SMS4 secret key in the initialized IppsSMS4Spec context.


Syntax
------


IppStatus ippsSMS4SetKey(const Ipp8u\* pKey, int keyLen, IppsSMS4Spec\*
pCtx);


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
     -  Length of the secret key.
   * -     pCtx   
     -  Pointer to the initialized IppsSMS4Spec context.




Description
-----------


This function resets the SMS4 secret key in the initialized IppsSMS4Spec
context with the user-supplied secret key.


.. note::


   If the pKey pointer is NULL, the function resets the context with the
   zero key, which can help you to clean up the actual secret before
   releasing the context.


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
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



.. rubric:: Related Information

:ref:`data-security-considerations`
