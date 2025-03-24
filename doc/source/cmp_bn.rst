.. _cmp_bn:

Cmp_BN
======


Compares two Big Numbers.


Syntax
------


IppStatus ippsCmp_BN(const IppsBigNumState\* pA, const IppsBigNumState\*
pB, Ipp32u\* pResult);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the context of the Big Number A.
   * - pB   
     - Pointer to the context of the Big Number B.
   * - pResult   
     - Pointer to the result of the comparison.




Description
-----------


This function compares Big Numbers A and B and sets up the result
according to the following conditions:


-  if A==B, then pResult = IS_ZERO
-  if A > B, then pResult = GREATER_THAN_ZERO
-  if A < B, then pResult = LESS_THAN_ZERO


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.



