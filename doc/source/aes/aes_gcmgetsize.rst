.. _aes_gcmgetsize:


AES_GCMGetSize
==============


Gets the size of the IppsAES_GCMState context for use of the AES-GCM
implementation with the specified characteristics.


Syntax
------


IppStatus ippsAES_GCMGetSize(int\* pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pSize   
     - Pointer to the size of the IppsAES_GCMState context.




Description
-----------


The function gets the size of the IppsAES_GCMState context (in bytes)
and stores the size in \*pSize.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if the specified pointer is NULL.



