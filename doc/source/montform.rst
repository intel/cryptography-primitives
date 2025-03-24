.. _montform:


MontForm
========


Converts input positive integer big number into Montgomery form.


Syntax
------


IppStatus ippsMontForm(const IppsBigNumState\* pA, IppsMontState\* pCtx,
IppsBigNumState\* pR);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pA   
     -  Pointer to the input integer big number within the range [0, pCtx- 1].
   * -     pCtx   
     -  Pointer to the input big number modulus of IppsBigNumState.
   * -     pR   
     -  Pointer to the resulting Montgomery form pR = pA\*\ ``R``\ ``mod``\ pCtx.




Description
-----------


The function converts an input positive integer big number into the
Montgomery form with respect to the big number modulus and stores the
conversion result.


The following pseudocode represents this function:


pR←pA\*\ ``R``\ ``mod``\ pCtx.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsBadArgErr   
     -  Indicates an error condition if pA is a negative integer.
   * -     ippStsScaleRangeErr   
     -  Indicates an error condition if pA is more than pCtx.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if IppsBigNumState \*pR is larger than IppsMontState \*m.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the context parameters does not match the operation.




.. note::


   The size of IppsBigNumState \*pR should not be less than the data
   length of the modulus pCtx.

