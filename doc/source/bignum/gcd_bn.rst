.. _gcd_bn:



Gcd_BN
======


Computes greatest common divisor.


Syntax
------


IppStatus ippsGcd_BN(IppsBigNumState\* pA, IppsBigNumState\* pB,
IppsBigNumState\* pGCD);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the first integer big number of IppsBigNumState.
   * - pB   
     - Pointer to the second integer big number of IppsBigNumState.
   * - pCGD   
     - Pointer to the greatest common divisor to pA and pB.




Description
-----------


The function computes the greatest common divisor (GCD) for two positive
integer big numbers.


The following pseudocode represents this function:


``pCGD``\ ←\ ``gcd`` (``pA`` ,\ ``pB``).


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition if IppsBigNumState\*pCGD is smaller than the length of IppsBigNumState\*pA or IppsBigNumState\*pB.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the context parameters does not match the operation.




.. note::


   The size of IppsBigNumState \*pCGD should not be less than either the
   length of IppsBigNumState \*pA and IppsBigNumState \*pB.

