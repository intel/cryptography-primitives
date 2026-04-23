.. _prngen:


PRNGen
======


Generates a pseudorandom unsigned Big Number of the specified bit
length.


Syntax
------


IppStatus ippsPRNGen(Ipp32u\* pRand, int nBits, void\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pRand   
     -  Pointer to the output pseudorandom unsigned integer big number.
   * -     nBits   
     -  The number of the generated pseudorandom bits.
   * -     pCtx   
     -  Pointer to the IppsPRNGState context.




Description
-----------


The function generates a pseudorandom unsigned integer big number of the
specified nBits length.


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
   * -     ippStsLengthErr   
     -  Indicates an error condition if nBits is less than 1.



