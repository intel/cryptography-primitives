.. _dlpinit:

DLPInit
=======


Initializes user-supplied memory as the IppsDLPState context for future
use.


Syntax
------


IppStatus ippsDLPInit(int peBits, int reBits, IppsDLPState\* pCtx);


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
   * - pCtx   
     - Pointer to the IppsDLPState context being initialized.




Description
-----------


The function initializes the memory pointed by pCtx as the IppsDLPState
context.


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


.. rubric:: Related Information

:ref:`data-security-considerations`

