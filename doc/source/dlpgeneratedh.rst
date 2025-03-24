.. _dlpgeneratedh:

DLPGenerateDH
=============


Generates domain parameters of the DL-based cryptosystem over GF(p) to
use the DH Agreement scheme.


Syntax
------


IppStatus ippsDLPGenerateDH(const IppsBigNumState\* pSeedIn, int
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
over GF(*p*) to use Diffie-Hellman Agreement scheme. The function uses a
procedure specified in
:term:`X9.42 <[X9.42]>` for
generating both randomized prime *p* and *r* based on the input
\*pSeedIn.


Generated primes *r* and *p* are further validated through a
nTrial-round Miller-Rabin primality test. Both generation and primality
test procedures employ specified rndFunc Random Generator.


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
     - Indicates an error condition if: peBits < 512 or reBits < 160, peBits is not divided by 256.
   * - ippStsRangeErr   
     - Indicates an error condition if: bitsize of the input *Seed* value is less than reBits, not enough space to store the output *Seed* value (if requested).
   * - ippStsBadArgErr   
     - Indicates an error condition if nTrials < 1.
   * - ippStsInsuffucientEntropy   
     - Indicates a warning condition if prime generation fails due to a poor choice of the entropy.



