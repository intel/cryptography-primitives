.. _prngsetmodulus:



PRNGSetModulus
==============


Sets the initial state with the given input modulus for the pseudorandom
number generation.


Syntax
------


IppStatus ippsPRNGSetModulus(const IppsBigNumState\* pMod,
IppsPRNGState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pMod
     -  Pointer to the modulus value being set up.
   * -     pCtx
     -  Pointer to the IppsPRNGState context.




Description
-----------


The function resets the modulus value with the supplied value up to 160
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
   * -     ippStsBadArgErr
     -  Indicates an error condition if the size of pMod is not 160 bit.



