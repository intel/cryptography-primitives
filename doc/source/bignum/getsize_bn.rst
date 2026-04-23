.. _getsize_bn:


GetSize_BN
==========


Returns the maximum length of the integer big number the structure can
store.


Syntax
------


IppStatus ippsGetSize_BN(const IppsBigNumState \*pBN, int \*pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pBN   
     - Integer big number of the data type IppsBigNumState.
   * - pSize   
     - Pointer to the maximum length of the integer big number.




Description
-----------


The function evaluates the working buffer assigned to the context
IppsBigNumState and returns the size of the structure to indicate the
maximum length of the integer big number that the structure can store.


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



