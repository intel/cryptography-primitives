.. _gfpecpointgetsize:


GFpECPointGetSize
=================


Gets the size of the IppsGFpECPoint context of a point on an elliptic
curve.


Syntax
------


IppStatus ippsGFpECPointGetSize(const IppsGFpECState\* pEC, int\*
pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pEC   
     - Pointer to the context of the elliptic curve.
   * - pSize   
     - Buffer size, in bytes, needed for the IppsGFpECPoint context.




Description
-----------


This function returns the size of the buffer associated with the
IppsGFpECPoint context, which you may use to store data for a point on
the elliptic curve over the finite field.


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



