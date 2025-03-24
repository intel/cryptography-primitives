.. _despack-desunpack:


DESPack, DESUnpack
==================


Packs/unpacks the IppsDESSpec context into/from a user-defined buffer
(deprecated).


Syntax
------


IppStatus ippsDESPack(const IppsDESSpec\* pCtx, Ipp8u\* pBuffer);


IppStatus ippsDESUnpack(const Ipp8u\* pBuffer, IppsDESSpec\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pCtx
     - Pointer to the IppsDESSpec context.
   * - pBuffer
     - Pointer to the user-defined buffer.




Description
-----------


.. note::


   This algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: AES.


The DESPack function transforms the \*pCtx context to a
position-independent form and stores it in the \*pBuffer buffer. The
DESUnpack function performs the inverse operation, that is, transforms
the contents of the \*pBuffer bufferinto a normal IppsDESSpec context.
The DESPack and DESUnpackfunctions enable replacing the
position-dependent IppsDESSpec contextin the memory.


Call the
:ref:`DESGetSize <desgetsize>`
functionprior to DESPack/DESUnpack to determine the size of the buffer.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr
     - Indicates an error condition if the pCtx pointer does not contain the IppsDESSpec context.



