.. _gfpeckeyexchangesm2_getsize:

GFpECKeyExchangeSM2_GetSize
===========================

Gets the size of the SM2 Key Exchange Elliptic Curve context. 

Syntax
-------

IppStatus ippsGFpECKeyExchangeSM2_GetSize(const IppsGFpECState* pEC, int* pSize)

Include Files
-------------

``ippcp.h``

Parameters 
----------


.. list-table:: 
   :header-rows: 0

   * - pEC
     - Pointer to the elliptic curve context.
   * - pSize
     - Pointer to the size, in bytes, of the IppsGFpECKeyExchangeSM2State context.


Description
-----------

The function computes the size of the buffer, in bytes, for the ``IppsGFpECKeyExchangeSM2State`` context to be used later. 
The pEC parameter represents a properly initialized elliptic curve using the SM2 Key Exchange scheme.


Return Values 
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers are NULL.
   * - ippStsContextMatchErr 
     - Indicates an error condition if the ``IppsGFpECState`` context parameter does not match the operation.
