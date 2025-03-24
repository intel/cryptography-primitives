.. _aes_gcmstart:



AES_GCMStart
============


Starts the process of authenticated encryption/decryption for new
message.


Syntax
------


IppStatus ippsAES_GCMStart(const Ipp8u\* pIV, int ivLen, const Ipp8u\*
pAAD, int aadLen, IppsAES_GCMState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pIV   
     - Pointer to the initialization vector.
   * - ivLen   
     - Length of the initialization vector \*pIV (in bytes).
   * - pAAD   
     - Pointer to the additional authenticated data.
   * - aadLen   
     - Length of additional authenticated data \*pAAD (in bytes).
   * - pState   
     - Pointer to the IppsAES_GCMState context.




Description
-----------


The function resets internal counters and buffers of the \*pState
context.


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
   * - ippStsLengthErr    
     - Indicates an error condition if the length of the initialization vector is zero.



