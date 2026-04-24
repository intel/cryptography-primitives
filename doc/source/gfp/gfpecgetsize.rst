.. _gfpecgetsize:

GFpECGetSize
============


Gets the size of an elliptic curve over the finite field.


Syntax
------


IppStatus ippsGFpECGetSize(const IppsGFpState\* pGF, int\* pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pGF   
     - Pointer to the IppsGFpState context of the underlying finite field.
   * - pSize   
     - Buffer size in bytes needed for the IppsGFpECState context.




Description
-----------


This function returns the size of the buffer associated with the
IppsGFpECState context, suitable for storing data for the elliptic curve
over the finite field specified by the context pGF.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the IppsGFpState context parameter does not match the operation.



