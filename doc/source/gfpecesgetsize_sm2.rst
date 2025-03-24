.. _gfpecesgetsize_sm2:

GFpECESGetSize_SM2
==================


Gets the size of the SM2 elliptic curve encryption context.


Syntax
------


IppStatus ippsGFpECESGetSize_SM2(const IppsGFpECState\* pEC, int\*
pSize);


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
     - Pointer to the size, in bytes, of the ECES context.




Description
-----------


The function computes the size of the buffer in bytes for the
IppsECES_StateSM2 context to be used later. The pEC parameter represents
a properly initialized elliptic curve using the encryption scheme.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr    
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the IppsGFpECState context parameter does not match the operation.
   * - ippStsNotSupportedModeErr   
     - Indicates an error condition if the IppsGFpECState context parameter defines an elliptic curve over an extension of the prime finite field.



