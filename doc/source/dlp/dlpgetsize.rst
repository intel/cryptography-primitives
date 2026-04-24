.. _dlpgetsize:


DLPGetSize
==========


Gets the size of the IppsDLPState context.


Syntax
------


IppStatus ippsDLPGetSize(int peBits, int reBits, int \*pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - peBits   
     - Bitsize of the GF(``p``) element (that is, the length of the DL-based cryptosystem in bits)
   * - reBits   
     - Bitsize of the multiplicative subgroup GF(``r``).
   * - pSize   
     - Pointer to the IppsDLPState context size in bytes.




Description
-----------


The function gets the IppsDLPState context size in bytes and stores in
\*pSize. DL-based cryptosystem over GF(``p``) assumes that ``r/p``-1
where both ``p`` and ``r`` are primes.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsSizeErr   
     - Indicates an error condition if peBits≤ reBits.



