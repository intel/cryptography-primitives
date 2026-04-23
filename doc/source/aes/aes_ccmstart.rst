.. _aes_ccmstart:


AES_CCMStart
============


Starts the process of authenticated encryption/decryption for a new
message.


Syntax
------


IppStatus ippsAES_CCMStart(const Ipp8u\* pIV, int ivLen, const Ipp8u\*
pAD, int adLen, IppsAES_CCMState\* pCtx);


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
   * - pAD   
     - Pointer to the additional authenticated data.
   * - adLen   
     - Length of additional authenticated data \*pAAD (in bytes).
   * - pCtx   
     - Pointer to the IppsAES_CCMState context.




Description
-----------


The function resets internal counters and buffers of the \*pCtx context.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr    
     - Indicates no error. Any other value indicates an error or warning.
   * - pState   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - pState   
     - Indicates an error condition if the context parameter does not match the operation.
   * - pState   
     - Indicates an error condition if ivLen < 7 or ivLen > 13 .



