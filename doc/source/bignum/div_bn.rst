.. _div_bn:



Div_BN
======


Divides one integer big number by another.


Syntax
------


IppStatus ippsDiv_BN(IppsBigNumState \*pA, IppsBigNumState \*pB,
IppsBigNumState \*pQ, IppsBigNumState \*pR);


Include Files
-------------

``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the dividend of IppsBigNumState.
   * - pB   
     - Pointer to the divisor of IppsBigNumState.
   * - pQ   
     - Pointer to the quotient of IppsBigNumState.
   * - pR   
     - Pointer to the remainder of IppsBigNumState.




Description
-----------


The function divides an integer big number dividend by another integer
big number regardless of their signs and sizes and returns the quotient
of the division and the respective remainder.


The following pseudocode represents this function:


``pQ``\ ←\ ``pA``/``pB``


``pR``\ ←\ ``pA`` - ``pB*pQ`` .


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition if IppsBigNumState \*pR is smaller than the length of IppsBigNumState \*pB or when the size of IppsBigNumState \*pQ is smaller than the quotient result data length.
   * - ippStsDivByZeroErr   
     - Indicates an error condition if the zero divisor is attempted.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the context parameters does not match the operation.




.. note::


   The size of IppsBigNumState \*pQ should not be less than (lengthof
   \*pA) - (length of \*pB) + 1, and the size of IppsBigNumState \*pR
   should be not less than the length of IppsBigNumState \*pB.

