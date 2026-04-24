.. _users-implementation-mask-gen-funct:


User's Implementation of a Mask Generation Function
===================================================


In case you prefer or have to use a different implementation of an MGF
you can still use IPPCP. To do this, use the definition of MGF
introduced in the IPPCP library and described in this section. The
declaration provided below also defines an MGF when it is used as a
parameter in some Public Key Cryptography operations.


Syntax
------


typedef IppStatus(_STDCALL \*IppMGF)(const Ipp8u\* pSeed, int seedLen,
Ipp8u\* pMask, int maskLen);


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pSeed
     -  Pointer to the input octet string.
   * -     seedLen
     -  Length of the input string.
   * -     pMask
     -  Pointer to the output pseodorandom mask.
   * -     maskLen
     -  Desired length of the output.




Description
-----------


This declaration is included in the ippcp.h file. The function generates
an octet string of length maskLen according to the implemented
algorithm, providing pseudorandom output.

