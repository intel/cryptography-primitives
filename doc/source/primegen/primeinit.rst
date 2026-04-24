.. _primeinit:

PrimeInit
=========


Initializes user-supplied memory as IppsPrimeState context for future
use.


Syntax
------


IppStatus ippsPrimeInit(int nMaxBits, IppsPrimeState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     nMaxBits    
     -  Maximum length of the probable prime number in bits.
   * -     pCtx   
     -  Pointer to the IppsPrimeState context being initialized.




Description
-----------


The function initializes the memory pointed by pCtx as the
IppsPrimeState context.


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



.. rubric:: Related Information

:ref:`data-security-considerations`

