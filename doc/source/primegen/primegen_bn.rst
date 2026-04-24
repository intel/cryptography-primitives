.. _primegen_bn:



PrimeGen_BN
===========


Generates a random probable prime number of the specified bitlength.


Syntax
------


IppStatus ippsPrimeGen_BN(IppsBigNumState\* pPrime, int nBits, int
nTrials, IppsPrimeState\* pCtx, IppBitSupplier rndFunc, void\*
pRndParam);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pPrime   
     -  Big number to store the generated number in.
   * -     nBits    
     -  Target bitlength for the desired probable prime number.
   * -     nTrials   
     -  Security parameter specified for the Miller-Rabin probable primality.
   * -     pCtx    
     -  Pointer to the IppsPrimeState context.
   * -     rndFunc   
     -  Specified Random Generator.
   * -     pRndParam   
     -  Pointer to the Random Generator context.




Description
-----------


The function employs the rndFuncRandom Generator specified by the user
to generate a random probable prime number of the nBits length and
stores the generated probable prime number in the pPrime big number. The
generated probable prime number is further validated by the Miller-Rabin
primality test scheme with the specified security parameter nTrials.


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
   * -     ippStsBadArgErr   
     -  Indicates an error condition if nTrials is less than 1.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if nBits > nMaxBits (see :ref:`PrimeGetSize <primegetsize>` and :ref:`PrimeInit <primeinit>`)
   * -     ippStsInsufficientEntropy   
     -  Indicates a warning condition if prime generation fails due to poor choice of entropy.



