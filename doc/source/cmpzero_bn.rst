.. _cmpzero_bn:


CmpZero_BN
==========


Checks the value of the input data field.


Syntax
------


IppStatus ippsCmpZero_BN(const IppsBigNumState\* pBN, Ipp32u\* pResult);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pBN   
     - Integer big number of the data type IppsBigNumState.
   * - pResult    
     - Indicates whether the input integer big number is positive, negative, or zero.




Description
-----------


The function scans the data field of the input const IppsBigNumState
\*pBN and returns:

*  IS_ZERO if the value held by IppsBigNumState \*pBN is zero
*  GREATER_THAN_ZERO if the input is more than zero
*  LESS_THAN_ZERO if the input is less than zero.


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



