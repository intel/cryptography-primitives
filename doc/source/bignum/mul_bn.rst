.. _mul_bn:


Mul_BN
======


Multiplies two integer big numbers.


Syntax
------


IppStatus ippsMul_BN(IppsBigNumState\* pA, IppsBigNumState\* pB,
IppsBigNumState\* pR);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the multiplicand of IppsBigNumState.
   * -     pB   
     -  Pointer to the multiplier of IppsBigNumState.
   * -     pR   
     -  Pointer to the multiplication result.




Description
-----------


The function multiplies an integer big number by another integer big
number regardless of their signs and sizes and returns the result of the
operation.


The following pseudocode represents this function:


``pR``\ ←\ ``pA`` \*\ ``pB``.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if IppsBigNumState \*r is smaller than the result data length.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if ant of the context parameters does not match the operation.




.. note::


   The function executes only under the condition that the size
   IppsBigNumState \*pR is not less than the sum of the lengths of
   IppsBigNumState \*pA or that of IppsBigNumState \*pB minus one.

