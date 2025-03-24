.. _dlpgeneratedsa:


DLPGenerateDSA
==============


Generates domain parameters of the DL-based cryptosystem over GF(p) to
use DSA.


Syntax
------


IppStatus ippsDLPGenerateDSA(const IppsBigNumState\* pSeedIn, int
nTrials, IppsDLPState\* pCtx, IppsBigNumState\* pSeedOut, int\*
pCounter, IppBitSupplier rndFunc, void\* pRndParam);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pSeedIn   
     - Pointer to the input *Seed*.
   * - nTrials   
     - Security parameter specified for the Miller-Rabin probable primality.
   * - pCtx   
     - Pointer to the cryptosystem context.
   * - pSeedOut   
     - Pointer to the output *Seed* value (if requested).
   * - pCounter   
     - Pointer to the *counter* value (if requested).
   * - rndFunc   
     - Specified Random Generator.
   * - pRndParam   
     - Pointer to the Random Generator context.




Description
-----------


The function generates domain parameters of the DL-based cryptosystem
over GF(*p*) to use DSA. The function uses a procedure specified in
:term:`FIPS PUB 186-2 <[FIPS PUB 186-2]>` for
generating both a 160-bit randomized prime r and a *LpeBits* prime *p*
based on the input \*pSeedIn.


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
   * - ippStsSizeErr   
     - Indicates an error condition if: peBits < 512, peBits is not divided by 64, reBits != 160.
   * - ippStsRangeErr   
     - Indicates an error condition if: bitsize of the input *Seed* value is less than 160, bitsize of the input *Seed* value is greater than peBits, not enough space to store the output *Seed* value (if requested).
   * - ippStsBadArgErr   
     - Indicates an error condition if nTrials < 1.
   * - ippStsInsuffucientEntropy   
     - Indicates a warning condition if prime generation fails due to a poor choice of the entropy.



