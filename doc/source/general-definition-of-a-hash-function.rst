.. _general-definition-of-a-hash-function:


General Definition of a Hash Function
=====================================


Syntax
------


typedef IppStatus(_STDCALL \*IppHASH)(const Ipp8u\* pMsg, int msgLen,
Ipp8u\* pMD);


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pMsg
     - Pointer to the input octet string.
   * - msgLen
     - Length of the input string in octers.
   * - pMD
     - Pointer to the output message digest.




Description
-----------


This declaration is included in the ippcp.h file. The function
calculates the digest of a non-streaming message using the implemented
hash algorithm.


.. note::


   Definition of a hash function used in Intel® Cryptography Primitives Library limits length (in
   octets) of an input message for any specific hash function by the
   range of the int data type, with the upper bound of 2\ :sup:`32`-1.

