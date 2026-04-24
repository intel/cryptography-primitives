.. _gfpecesinit_sm2:



GFpECESInit_SM2
===============


Initializes the ECES context.


Syntax
------


IppStatus ippsGFpECESInit_SM2(IppsGFpECState\* pEC, IppsECES_StateSM2\*
pState, int availableCtxSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pEC   
     - Pointer to the elliptic curve context used in the ECES.
   * - pState   
     - Pointer to the buffer being initialized as the ECES context.
   * - availableCtxSize   
     - Available size of the buffer being initialized.




Description
-----------


The function initializes the memory buffer pointed to by pState as
IppsECES_StateSM2.


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
   * - ippStsSizeErr   
     - Indicates an error condition if size of the initialized buffer is not big enough for the operation.



