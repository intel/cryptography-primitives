.. _get_bn:

Get_BN
======


Extracts the sign and value of the integer big number from the input
structure.


Syntax
------


IppStatus ippsGet_BN(IppsBigNumSGN \*sgn, int\* pLength, Ipp32u\* pData,
const IppsBigNumState\* pBN);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - sgn   
     - Sign of IppsBigNumState \*x.
   * - pLength   
     - Pointer to the array length of the input data.
   * - pData   
     - Pointer to the data array.
   * - pBN   
     - Integer big number of the context IppsBigNumState.




Description
-----------


The function extracts the sign and value of the integer big number from
the input structure.


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



