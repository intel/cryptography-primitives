.. _mod_bn:



Mod_BN
======


Computes modular reduction for input integer big number with respect to
specified modulus.


Syntax
------


IppStatus ippsMod_BN(IppsBigNumState \*pA, IppsBigNumState \*pM,
IppsBigNumState \*pR);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the integer big number of IppsBigNumState.
   * -     pM   
     -  Pointer to the modulus integer of IppsBigNumState.
   * -     pR   
     -  Pointer to the modular reduction result.




Description
-----------


The function computes the modular reduction for an input integer big
number with respect to the modulus specified by a positive integer big
number and returns the modular reduction result in the range of [0,
(m-1)].


The following pseudocode represents this function:


``pR``\ ←\ ``pA``\ ``mod pM``.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if IppsBigNumState \*pR is smaller than the length of IppsBigNumState \*m.
   * -     ippStsBadModulusErr   
     -  Indicates an error condition if the modulus IppsBigNumState \*pM is not a positive integer.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the context parameters does not match the operation.




.. note::


   The size of IppsBigNumState \*pR should not be less than the length
   of IppsBigNumState \*pM.

