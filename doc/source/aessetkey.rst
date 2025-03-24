.. _aessetkey:


AESSetKey
=========


Resets the AES secret key in the initialized IppsAESSpec context.


Syntax
------


IppStatus ippsAESSetKey(const Ipp8u\* pKey, int keylen, IppsAESSpec\*
pCtx);


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
     - Length of the secret key.
   * - pCtx   
     - Pointer to the initialized IppsAESSpec context.




Description
-----------


This function resets the AES secret key in the initialized IppsAESSpec
context with the user-supplied secret key.


.. note::


   If the pKey pointer is NULL, the function resets the context with the
   zero key, which can help you to clean up the actual secret before
   releasing the context.


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


.. rubric:: Related Information 

:ref:`data-security-considerations`

