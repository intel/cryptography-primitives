.. _users-implementation-of-a-pseudorandom-num-gen:



User's Implementation of a Pseudorandom Number Generator
========================================================


Both functions ippsPRNGGen and ippsPRNGGen_BN, as well as their
supplementary functions represent the implementation of the pseudorandom
number generator in the IPPCP library. This given implementation is
based on recommendations made in :term:`FIPS PUB 186-2 <[FIPS PUB 186-2]>`. If
you prefer to use the implementation of the pseudorandom number
generator which is different from the given, you can still use IPPCP
library. To do this, use the following definition of the generator
introduced by the IPPCP library:


Syntax
------


typedef IppStatus(_STDCALL \*IppBitSupplier)(Ipp32u\* pData, int nBits,
void\* pEbsParams);


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pData
     -  Pointer to the output data.
   * -     nBits
     -  Number of generated data bits.
   * -     pEbsParams
     -  Pointer to the user defined context.




Description
-----------


This declaration is included in the ippcp.h file. The function generates
any data (probably pseudorandom numbers) of the specified nBits length.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsErr
     -  Indicates an error condition.



