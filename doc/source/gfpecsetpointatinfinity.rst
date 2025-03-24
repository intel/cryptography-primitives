.. _gfpecsetpointatinfinity:




GFpECSetPointAtInfinity
=======================


Sets a point on an elliptic curve as a point at infinity.


Syntax
------


IppStatus ippsGFpECSetPointAtInfinity(IppsGFpECPoint\* pPoint,
IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pPoint   
     - Pointer to the IppsGFpECPoint context.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function sets the coordinates of an elliptic curve point in the
IppsGFpECPoint context to the coordinates of a point at infinity.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if pPoint or pEC is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if the IppsGFpECState or IppsGFpECPoint context parameter does not match the operation.



