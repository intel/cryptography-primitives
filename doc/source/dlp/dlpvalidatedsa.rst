.. _dlpvalidatedsa:



DLPValidateDSA
==============


Validates domain parameters of the DL-based cryptosystem over GF(p) to
use DSA.


Syntax
------


IppStatus ippsDLPValidateDSA(int nTrials, IppDLResult\* pResult,
IppsDLPState\* pCtx, IppBitSupplier rndFunc, void\* pRndParam);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - nTrials   
     - Security parameter specified for the Miller-Rabin probable primality.
   * - pResult   
     - Pointer to the validation result.
   * - pCtx   
     - Pointer to the cryptosystem context.
   * - rndFunc   
     - Specified Random Generator.
   * - pRndParam   
     - Pointer to the Random Generator context.




Description
-----------


The function validates domain parameters of the DL-based cryptosystem
over GF(*p*) to use DSA. The result of validation is stored in the
\*pResult and may be assigned to one of the enumerators listed below:


.. list-table:: 
   :header-rows: 0

   * - ippDLValid   
     - Validation has passed successfully.
   * - ippDLBaseIsEven   
     - ``P`` is even.
   * - ippDLOrderIsEven   
     - ``R`` is even.
   * - ippDLInvalidBaseRange   
     - ``P``\ ≤ 2\ :sup:`peBits-1`\ or ``P``\ ≥ 2\ :sup:`peBits`.
   * - ippDLInvalidOrderRange   
     - ``R``\ ≤ 2\ :sup:`reBits-1`\ or ``R``\ ≥ 2\ :sup:`reBits`.
   * - ippDLCompositeBase   
     - ``P`` is not a prime.
   * - ippDLCompositeOrder   
     - ``R`` is not a prime.
   * - ippDLInvalidCofactor   
     - ``R`` is not divisible by (``P`` -1).
   * - ippDLInvalidGenerator   
     - (1 < *``G``* < (``P`` -1)) is false or *``G``*\ ^\ ``R`` != 1 (mod ``P``).




To ensure that both *p* and *r* are primes, the function applies
nTrial-round Miller-Rabin primality test. Test data for primality test
is provided by the specified rndFunc Random Generator.


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
   * - ippStsIncompleteContextErr   
     - Indicates an error condition if the cryptosystem context has not been properly set up.
   * - ippStsBadArgErr   
     - Indicates an error condition if nTrials < 1.



