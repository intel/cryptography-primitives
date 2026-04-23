.. _prnggetsize:


PRNGGetSize
===========


Gets the size of the IppsPRNGState context in bytes.


Syntax
------


IppStatus ippsPRNGGetSize(int \*pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSize   
     -  Pointer to the IppsPRNGState context size in bytes.




Description
-----------


The function gets the IppsPRNGState context size in bytes and stores it
in \*pSize.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.



