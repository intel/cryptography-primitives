.. _sub_bn:


Sub_BN
======


Subtracts one integer big number from another.


Syntax
------


IppStatus ippsSub_BN(IppsBigNumState\* pA, IppsBigNumState\* pB,
IppsBigNumState\* pR);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the first integer big number of the data type IppsBigNumState.
   * -     pB   
     -  Pointer to the second integer big number of the data type IppsBigNumState.
   * -     pR   
     -  Pointer to the subtraction result.




Description
-----------


The function subtracts one integer big number from another regardless of
their signs and sizes and returns the result of the operation.


The following pseudocode represents this function:


(\*\ ``pR``) ← (\*\ ``pA``) - (\*\ ``pB``).


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if IppsBigNumState \*pR is smaller than the result data length.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the context parameters does not match the operation.




.. note::


   The function executes only under the condition that size of
   IppsBigNumState \*pR is not less than either the length of
   IppsBigNumState \*pA or that of IppsBigNumState \*pB.

