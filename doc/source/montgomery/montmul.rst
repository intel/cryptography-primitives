.. _montmul:


MontMul
=======


Computes Montgomery modular multiplication for positive integer big
numbers of Montgomery form.


Syntax
------


IppStatus ippsMontMul(const IppsBigNumState \*pA, const IppsBigNumState
\*pB, IppsMontState \*m, IppsBigNumState \*pR);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the multiplicand within the range [0, m- 1].
   * -     pB   
     -  Pointer to the multiplier within the range [0, m- 1].
   * -     m   
     -  Modulus.
   * -     pR   
     -  Pointer to the montgomery multiplication result.




Description
-----------


The function computes the Montgomery modular multiplication for positive
integer big numbers of Montgomery form with respect to the modulus
IppsMontState \*m. As a result, IppsBigNumState \*pR holds the product.


The following pseudocode represents this function:


pR←pA\*pB\*R\ :sup:`-1`\ mod m.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsBadArgErr   
     -  Indicates an error condition if pA or pB is a negative integer.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsScaleRangeErr   
     -  Indicates an error condition if pA or pB is more than m.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if IppsBigNumState \*pRis larger than IppsMontState \*m.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the context parameters does not match the operation.




.. note::


   The size of IppsBigNumState \*pR should not be less than the data
   length of the modulus m.

