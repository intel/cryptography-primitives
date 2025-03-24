.. _primeget:



PrimeGet
========


Extracts the probable prime unsigned integer big number.


Syntax
------


IppStatus ippsPrimeGet(Ipp32u\* pBNU, int \*pSize, const IppsPrimeState
\*pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pBNU
     -  Pointer to the unsigned integer big number.
   * -     pSize
     -  Pointer to the length of the unsigned integer big number.
   * -     pCtx
     -  Pointer to the IppsPrimeState context.




Description
-----------


The function extracts the probable prime number from \*pCtx context and
stores it into the specified unsigned integer big number.


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



