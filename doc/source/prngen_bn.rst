.. _prngen_bn:


PRNGen_BN
=========


Generates a pseudorandom positive Big Number of the specified bitlength.


Syntax
------


IppStatus ippsPRNGen_BN(IppsBigNumState\* pRandBN, int nBits, void\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pRandBN   
     -  Pointer to the output pseudorandom Big Number.
   * -     nBits   
     -  Number of the generated pseudorandom bit.
   * -     pCtx   
     -  Pointer to the IppsPRNGState context.




Description
-----------


The function generates pseudorandom positive Big Number of the specified
nBits length.


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
   * -     ippStsLengthErr   
     -  Indicates an error condition if nBits is less than 1.



