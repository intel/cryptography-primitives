.. _mgf:


MGF
===


Generates a pseudorandom mask of the specified length using a selected
hash algorithm.


Syntax
------


IppStatus ippsMGF(const Ipp8u \*pSeed, int seedLen, Ipp8u\* pMask, int
maskLen, IppHashAlgId hashAlg);


Include Files
-------------


``ippcp.h``


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
   * -     hashAlg
     -  Identifier of the hash algorithm.




Description
-----------


The function generates a pseudorandom mask of the specified length using
the hash algorithm defined by algID. The hashAlg parameter can take one
of the values listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -     Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -      Indicates an error condition if pMask pointer is NULL.
   * -     ippStsLengthErr
     -      Indicates an error condition if any of the specified lengths is negative or zero.
   * -     ippStsNotSupportedModeErr
     -     Indicates an error condition if the hashAlg parameter does not
           match any value of IppHashAlg listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.



