.. _sms4getsize:


SMS4GetSize
===========


Gets the size of the IppsSMS4Spec context.


Syntax
------


IppStatus ippsSMS4GetSize(int\* pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSize   
     -  Pointer to the IppsSMS4Spec context size value.




Description
-----------


The function gets the IppsSMS4Spec context size in bytes and stores it
in \*pSize.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.



