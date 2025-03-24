.. _primeset_bn:


PrimeSet_BN
===========


Sets the Big Number for primality testing.


Syntax
------


IppStatus ippsPrimeSet_BN(const IppsBigNumState\* pBN, IppsPrimeState\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pBN   
     -  Pointer to the Big Number context.
   * -     pCtx   
     -  Pointer to the IppsPrimeState context.




Description
-----------


The function sets the Big Number for probabilistic primality test.


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
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if the Big Number is too large to fit pCtx.



