.. _arcfourpack-arcfourunpack:


ARCFourPack, ARCFourUnpack
==========================


Packs/unpacks the IppsARCFourSpec context into/from a user-defined
buffer (deprecated).


Syntax
------


IppStatus ippsARCFourPack (const IppsARCFourState\* pCtx, Ipp8u\*
pBuffer);


IppStatus ippsARCFourUnpack (const Ipp8u\* pBuffer, IppsARCFourState\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pCtx   
     - Pointer to the IppsARCFourState context.
   * - pBuffer   
     - Pointer to the user-defined buffer.




Description
-----------


.. note::


   These functions are deprecated.


The ARCFourPack function transforms the \*pCtx context to a
position-independent form and stores it in the \*pBuffer buffer. The
ARCFourUnpack function performs the inverse operation, that is,
transforms the contents of the \*pBuffer buffer into a normal
IppsARCFourState context. The ARCFourPack and ARCFourUnpack functions
enable replacing the position-dependent IppsARCFourState context in the
memory.


Call the
:ref:`ARCFourGetSize <arcfourgetsize>`
function prior to ARCFourPack/ARCFourUnpack to determine the size of the
buffer.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.



