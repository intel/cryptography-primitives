.. _aes_ccmgetsize:

AES_CCMGetSize
==============


Gets the size of the IppsAES_CCMState context.


Syntax
------


IppStatus ippsAES_CCMGetSize(int\* pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pSize   
     - Pointer to the size of the IppsAES_CCMState context.




Description
-----------


The function gets the size of the IppsAES_CCMState context in bytes and
stores it in \*pSize.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if the specified pointer is NULL.



