.. _aespack-aesunpack:


AESPack, AESUnpack
==================


Packs/unpacks the IppsAESSpec context into/from a user-defined buffer.


Syntax
------


IppStatus ippsAESPack (const IppsAESSpec\* pCtx, Ipp8u\* pBuffer, int
bufSize);


IppStatus ippsAESUnpack (const Ipp8u\* pBuffer, IppsAESSpec\* pCtx, int
ctxSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pCtx
     - Pointer to the IppsAESSpec context.
   * - pBuffer
     - Pointer to the user-defined buffer.
   * - bufSize
     - Available size of the buffer.
   * - ctxSize
     - Available size of the context.




Description
-----------


The AESPack function transforms the \*pCtx context to a
position-independent form and stores it in the \*pBuffer buffer. The
AESUnpack function performs the inverse operation, that is, transforms
the contents of the \*pBuffer buffer into a normal IppsAESSpec context.
The AESPack and AESUnpack functions enable replacing the
position-dependent IppsAESSpec context in the memory.


Call the :ref:`AESGetSize <aesgetsize>`
function prior to AESPack/AESUnpack to determine the size of the buffer.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr
     - Indicates an error condition if bufSize or ctxSize is less than the real size of the IppsAESSpec context.
   * - ippStsContextMatchErr
     - Indicates an error condition if the pCtx parameter does not match the operation.



