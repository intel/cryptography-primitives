.. _primegetsize:



PrimeGetSize
============


Gets the size of the IppsPrimeState context in bytes.


Syntax
------


IppStatus ippsPrimeGetSize(int nMaxBits, int\* pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     nMaxBits   
     -  Maximum length of the probable prime number in bits.
   * -     pSize   
     -  Pointer to the IppsPrimeState context size in bytes.




Description
-----------


The function gets the IppsPrimeState context size in bytes and stores it
in pSize.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr   
     -  Indicates an error condition if nMaxBits is less than 1.



