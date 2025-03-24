.. _prngseth0:




PRNGSetH0
=========


Sets the initial state with the given input IV for the SHA-1 algorithm.


Syntax
------


IppStatus ippsPRNGSetH0(const IppsBigNumState\* pH0, IppsPRNGState\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pH0
     -  Pointer to the initial hash value being set up.
   * -     pCtx
     -  Pointer to the IppsPRNGState context.




Description
-----------


The function resets the initial hash value with the supplied value up to
160 bit length. The supplied big number should be created prior to the
function call using the appropriate Big Number Arithmetic functions (see
:ref:`Example “Create a Big Number” <set_bn>`).


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



