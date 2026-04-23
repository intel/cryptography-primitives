.. _prnginit:



PRNGInit
========


Initializes user-supplied memory as IppsPRNGState context for future
use.


Syntax
------


IppStatus ippsPRNGInit(int seedBits, IppsPRNGState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     seedBits
     -  Size in bits for the seed value.
   * -     pCtx
     -  Pointer to the IppsPRNGState context being initialized.




Description
-----------


The function initializes the memory pointed by pCtx as the IppsPRNGState
context. In addition, the function sets up the default internal random
generator parameters (seed, entropy augment, modulus, and initial hash
value H0 of the SHA-1 algorithm). PRNG default parameters are as
follows:

-  seed =0x0
-  entropy augment =0x0
-  modulus =0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
-  H0 =0xC3D2E1F01032547698BADCFEEFCDAB8967452301


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsLengthErr
     -  Indicates an error condition if seedBits is less than 1 or greater than 512.




.. rubric:: Related Information

:ref:`data-security-considerations`
