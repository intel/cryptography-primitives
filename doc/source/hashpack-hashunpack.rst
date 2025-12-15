.. _hashpack-hashunpack:



HashPack, HashUnpack
====================


Packs/unpacks the IppsHashState or IppsHashState_rmf context into/from a
user-defined buffer.


Syntax
------


IppStatus ippsHashPack (const IppsHashState\* pCtx, Ipp8u\* pBuffer, int
bufSize);


IppStatus ippsHashPack_rmf(const IppsHashState_rmf\* pCtx, Ipp8u\*
pBuffer, int bufferSize);


IppStatus ippsHashUnpack (const Ipp8u\* pBuffer, IppsHashState\* pCtx);


IppStatus ippsHashUnpack_rmf(const Ipp8u\* pBuffer, IppsHashState_rmf\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pCtx
     -  Pointer to the IppsHashState or IppsHashState_rmf context.
   * -     pBuffer
     -  Pointer to the user-defined buffer.
   * -     bufSize, bufferSize
     -  The size of the user-defined buffer in bytes.




Description
-----------

.. note::


   ippsHashPack and ippsHashUnpack functions are deprecated. Please refer to
   :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The HashPack function transforms the \*pCtx context to a
position-independent form and stores it in the the \*pBuffer buffer. The
HashUnpack function performs the inverse operation, that is, transforms
the contents of the \*pBuffer buffer into a normal IppsHashState or
IppsHashState_rmf context. The HashPack and HashUnpack functions enable
replacing the position-dependent IppsHashState or IppsHashState_rmf
context in the memory.


The value of the bufSize parameter must be not less than the size of
IppsHashState or IppsHashState_rmf context. Call the
:ref:`HashGetSize <hashgetsize>`
function prior to HashPack to determine the size of the buffer.

.. note::

   The \*pCtx context has to be initialized before calling ippsHashUnpack_rmf.

.. note::


   This function has a *reduced memory footprint* version. To learn
   more, see :ref:`Reduced Memory Footprint Functions <one-way-hash-primitives>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -      Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -     Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsMemErr
     -     Indicates an error condition if the value of bufSize is less than the size of the IppsHashState context.
   * -     ippStsContextMatchErr
     -     Indicates an error condition in a ippsHashPack_rmf call if the context parameter does not match the operation.
   * -     ippStsNoMem
     -     Indicates an error condition if the value of bufferSize is less than the size of the IppsHashState_rmf context.
   * -     ippStsNotSupportedModeErr
     -     Indicates an error condition if the provided hash algorithm identifier is not supported.



