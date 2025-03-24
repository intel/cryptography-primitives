.. _prnggetseed:


PRNGGetSeed
===========


Extracts the seed value of the pseudorandom number generator from the
context structure.


Syntax
------


IppStatus ippsPRNGGetSeed(const IppsPRNGState\* pCtx, IppsBigNumState\*
pSeed);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pCtx   
     -  Pointer to the IppsPRNGState context.
   * -     pSeed    
     -  Pointer to the seed value.




Description
-----------


The function extracts the seed value of the pseudorandom number
generator from the IppsPRNGState context structure into a big number.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if \*pSeed is not a IppsBigNumState structure or \*pCtx is not a IppsPRNGState structure.
   * -     ippOutOfRangeErr   
     -  Indicates an error condition if the length of the actual seed exceeds \*pSeed.



