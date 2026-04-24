.. _hashmethodgetsize:



HashMethodGetSize
=================


Gets the size of the IppsHashMethod context in bytes.


Syntax
------


IppStatus ippsHashMethodGetSize(int \*pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -      pSize   
     -  Pointer to the value of the IppsHashMethod context size.




Description
-----------


The function gets the size of the IppsHashMethod context in bytes and
stores it in \*pSize.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -      ippStsNoErr   
     -  Indicates no errors. Any other value indicates an error or warning.
   * -      ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.



