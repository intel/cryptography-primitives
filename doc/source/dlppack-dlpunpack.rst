.. _dlppack-dlpunpack:


DLPPack, DLPUnpack
==================


Packs/unpacks the IppsDLPState context into/from a user-defined buffer.


Syntax
------


IppStatus ippsDLPPack (const IppsDLPState\* pCtx, Ipp8u\* pBuffer);


IppStatus ippsDLPUnpack (const Ipp8u\* pBuffer, IppsDLPState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pCtx   
     - Pointer to the IppsDLPState context.
   * - pBuffer   
     - Pointer to the user-defined buffer.




Description
-----------


The DLPPack function transforms the \*pCtx context to a
position-independent form and stores it in the the \*pBuffer buffer. The
DLPUnpack function performs the inverse operation, that is, transforms
the contents of the \*pBuffer buffer into a normal IppsDLPState context.
The DLPPack and DLPUnpack functions enable replacing the
position-dependent IppsDLPState context in the memory.


Call the
:ref:`DLPGetSize <dlpgetsize>`
function prior to DLPPack/DLPUnpack to determine the size of the buffer.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.



