.. _prngsetaugment:


PRNGSetAugment
==============


Sets the initial state with the given input entropy for the pseudorandom
number generation.


Syntax
------


IppStatus ippsPRNGSetAugment(const IppsBigNumState\* pAugment,
IppsPRNGState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pAugment
     -  Pointer to the entropy augment value being set up.
   * -     pCtx
     -  Pointer to the IppsPRNGState context.




Description
-----------


The function resets entropy augment value with the supplied value of the
seedBits bit length. The supplied big number should be created prior to
the function call using the appropriate Big Number Arithmetic functions
(see :ref:`Example “Create a Big
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



