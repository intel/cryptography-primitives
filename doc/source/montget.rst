.. _montget:

MontGet
=======


Extracts the big number modulus.


Syntax
------


IppStatus ippsMontGet(Ipp32u \*pModulo, int \*pSize, const IppsMontState
\*pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pCtx   
     -  Pointer to the context IppsMontState.
   * -     pModulo   
     -  Pointer to the modulus data field.
   * -     pSize   
     -  Pointer to the modulus data size in Ipp32u chunks.




Description
-----------


The function extracts the big number modulus from the input
IppsMontState \*pCtx.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if pCtx does not match the operation.



