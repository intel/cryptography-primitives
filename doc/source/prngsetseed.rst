.. _prngsetseed:



PRNGSetSeed
===========


Sets up the seed value for the pseudorandom number generator.


Syntax
------


IppStatus ippsPRNGSetSeed(const IppsBigNumState\* pSeed, IppsPRNGState\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pSeed
     -  Pointer to the seed value being set up.
   * -     pCtx
     -  Pointer to the IppsPRNGState context.




Description
-----------


The function resets the seed value with the supplied value of seedBits
bit length. The supplied big number should be created prior to the
function call using the appropriate Big Number Arithmetic functions (see
:ref:`Example “Create a Big
Number” <set_bn>`).


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




.. note::


   This function restarts the pseudorandom number generation process,
   which results in losing already generated pseudorandom numbers.

