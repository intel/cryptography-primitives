.. _aes_gcmreset:



AES_GCMReset
============


Resets the IppsAES_GCMState context for authenticated
encryption/decryption of a new message.


Syntax
------


IppStatus ippsAES_GCMReset(IppsAES_GCMState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pState   
     - Pointer to the IppsAES_GCMState context.




Description
-----------


The function resets the \*pState context to prepare it for either of the
following operations with a new message:

* encryption and tag generation
* decryption and tag authentication


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr    
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the context parameter does not match the operation.



