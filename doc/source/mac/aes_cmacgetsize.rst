.. _aes_cmacgetsize:



AES_CMACGetSize
===============


Gets the size of the IppsAES_CMACState context.


Syntax
------


IppStatus ippsAES_CMACGetSize(int \*pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pSize   
     - Pointer to the IppsAES_CMACState context.




Description
-----------


This function gets the size of the IppsAES_CMACState context.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.



