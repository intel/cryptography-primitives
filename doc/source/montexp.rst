.. _montexp:


MontExp
=======


Computes Montgomery exponentiation.


Syntax
------


IppStatus ippsMontExp(const IppsBigNumState \*pA, const IppsBigNumState
\*pE, IppsMontState \*m, IppsBigNumState \*pR);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the big number Montgomery integer within the range of [0, m- 1].
   * -     pE   
     -  Pointer to the big number exponent.
   * -     m   
     -  Modulus.
   * -     pR   
     -  Pointer to the montgomery exponentiation result.




Description
-----------


The function computes Montgomery exponentiation with the exponent
specified by the input positive integer big number to the given positive
integer big number of the Montgomery form with respect to the modulus m.


The following pseudocode represents this function:


pR←pA\ :sup:`pE`\ R\ :sup:`-(pE-1)`\ mod m.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsBadArgErr   
     -  Indicates an error condition if pA or pE is a negative integer.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsScaleRangeErr   
     -  Indicates an error condition if pA or pE is more than m.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if IppsBigNumState\*pRis larger than IppsMontState\*m.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the context parameters does not match the operation.




.. note::


   The size of IppsBigNumState \*pR should not be less than the data
   length of the modulus m.

