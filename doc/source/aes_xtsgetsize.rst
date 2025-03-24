.. _aes_xtsgetsize:



AES_XTSGetSize
==============


Gets the size of the IppsAES_XTSSpec context.


Syntax
------


IppStatus ippsAES_XTSGetSize(int\* pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pSize   
     - Pointer to the IppsAES_XTSSpec context size value.




Description
-----------


The function gets the size of the IppsAES_XTSSpec context in bytes and
stores it in \*pSize.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if the pSize pointer is NULL.



