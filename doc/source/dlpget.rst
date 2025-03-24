.. _dlpget:


DLPGet
======


Retrieves domain parameters of the DL-based cryptosystem over GF(p).


Syntax
------


IppStatus ippsDLPGet(IppsBigNumState\* pP, IppsBigNumState\* pQ,
IppsBigNumState\* pG, IppsDLPState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pP   
     - Pointer to the characteristic *p* of the prime finite field GF(*p*).
   * - pQ   
     - Pointer to the characteristic *q* of the multiplicative subgroup GF(*q*).
   * - pG   
     - Pointer to the generator *G* of the multiplicative subgroup GF(*r*).
   * - pCtx   
     - Pointer to the cryptosystem context.




Description
-----------


The function retrieves DL-based cryptosystem domain parameters into the
cryptosystem context.


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
   * - ippStsIncompleteContextErr   
     - Indicates an error condition if the cryptosystem context has not been properly set up.
   * - ippStsRangeErr   
     - Indicates an error condition if any of the Big Numbers specified by pP, pR, and pG is too small for the DL parameter.



