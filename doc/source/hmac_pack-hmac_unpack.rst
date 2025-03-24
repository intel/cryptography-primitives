.. _hmac_pack-hmac_unpack:


HMAC_Pack, HMAC_Unpack
======================


Packs/unpacks the IppsHMACState or IppsHMACState_rmf context into/from a
user-defined buffer.


Syntax
------


IppStatus ippsHMAC_Pack (const IppsHMACState\* pCtx, Ipp8u\* pBuffer,
int bufSize);


IppStatus ippsHMACPack_rmf (const IppsHMACState_rmf\* pCtx, Ipp8u\*
pBuffer, int bufSize);


IppStatus ippsHMAC_Unpack (const Ipp8u\* pBuffer, IppsHMACState\* pCtx);


IppStatus ippsHMACUnpack_rmf (const Ipp8u\* pBuffer, IppsHMACState_rmf\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pCtx   
     -  Pointer to the IppsHMACState or IppsHMACState_rmf context.
   * -     pBuffer   
     -  Pointer to the user-defined buffer.
   * -     bufSize   
     -  The size of the user-defined buffer in bytes.




Description
-----------


The HMAC_Pack function transforms the \*pCtx context to a
position-independent form and stores it in the \*pBuffer buffer. The
HMAC_Unpack function performs the inverse operation, that is, transforms
the contents of the \*pBuffer buffer into a normal IppsHMACState or
IppsHMACState_rmf context. The HMAC_Pack and HMAC_Unpack functions
enable replacing the position-dependent IppsHMACState or
IppsHMACState_rmf context in the memory. Call the
:ref:`HMAC_GetSize <hmac_getsize>`
function prior to HMAC_Pack to determine the size of the buffer.


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
     -      Indicates an error condition if any of the specified pointers is NULL.    
   * -     ippStsMemErr   
     -      Indicates an error condition if the value of bufSize is less than the size of the IppsHMACState or IppsHMACState_rmf context.    



