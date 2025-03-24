.. _arcfourgetsize:


ARCFourGetSize
==============


Gets the size of the IppsARCFourState context (deprecated).


Syntax
------


IppStatus ippsARCFourGetSize(int\* pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pSize   
     - Pointer to the size value of the IppsARCFourState context.




Description
-----------


.. note::


   This function is deprecated.


The function gets the size of the IppsARCFourState context in bytes and
stores it in \*pSize.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if the specified pointer is NULL.



