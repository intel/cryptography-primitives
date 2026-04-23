.. _aes_ccmmessagelen:


AES_CCMMessageLen
=================


Sets up the length of the message to be processed.


Syntax
------


IppStatus ippsAES_CCMMessageLen(Ipp64u msgLen, IppsAES_CCMState\*
pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - msgLen   
     - Length of the message to be processed (in bytes).
   * - pState   
     - Pointer to the IppsAES_CCMState context.




Description
-----------


The function assigns the value of msgLen to the length of the message to
be processed in the \*pState context.


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
     - Indicates an error condition if msgLen=0.



