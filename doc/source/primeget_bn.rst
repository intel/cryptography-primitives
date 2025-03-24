.. _primeget_bn:


PrimeGet_BN
===========


Extracts the probable prime positive Big Number.


Syntax
------


IppStatus ippsPrimeGet_BN(IppsBigNumState\* pBN, const IppsPrimeState
\*pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pBN   
     -  Pointer to the Big NUmber context.
   * -     pCtx   
     -  Pointer to the IppsPrimeState context.




Description
-----------


The function extracts the probable prime positive big number from the
\*pCtx context and stores it into the specified Big Number context.


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
     -  Indicates an error condition if the Big Number is too small to store probable prime number.



