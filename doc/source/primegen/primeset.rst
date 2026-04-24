.. _primeset:



PrimeSet
========


Sets the Big Number for primality testing.


Syntax
------


IppStatus ippsPrimeSet(const Ipp32u\* pBNU, int nBits, IppsPrimeState\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pBNU   
     -  Pointer to the unsigned integer big number.
   * -     nBits    
     -  Unsigned integer big number length in bits.
   * -     pCtx   
     -  Pointer to the IppsPrimeState context.




Description
-----------


The function sets a probable prime number and its length for the
probabilistic primality test.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr   
     -  Indicates an error condition if nBits is less than 1.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the context parameter does not match the operation.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if nBits is too large to fit pCtx.



