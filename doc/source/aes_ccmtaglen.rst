.. _aes_ccmtaglen:


AES_CCMTagLen
=============


Sets up the length of the required authentication tag.


Syntax
------


IppStatus ippsAES_CCMTagLen(int tagLen, IppsAES_CCMState\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - tagLen   
     - Length of the required authentication tag (in bytes).
   * - pState   
     - Pointer to the IppsAES_CCMState context.




Description
-----------


The function assigns the value of tagLen to the length of the required
authentication tag in the \*pState context.


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
     - Indicates an error condition if tagLen < 4 or tagLen > 16 or taglen is odd.



