.. _gfpecesgetbuffersize_sm2:


GFpECESGetBufferSize_SM2
========================


Returns sizes of the ECES SM2 buffer components.


Syntax
------


IppStatus ippsGFpECESGetBufferSize_SM2(int\* pPubKeySize, int\*
pTagSize, const ippsECES_StateSM2\* pState);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pPubKeySize   
     - Pointer to the size of the public key representation.
   * - pTagSize   
     - Pointer to the maximum size of the authentication tag buffer.
   * - pState   
     - Pointer to the buffer being initialized as the ECES context.




Description
-----------


The function returns buffer sizes for the public key and authentication
tag representations.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr    
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the IppsECES_StateSM2 context parameter does not match the operation.



