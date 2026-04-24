.. _gfpecsetpoint-gfpecsetpointregular:


GFpECSetPoint, GFpECSetPointREgular
===================================


Sets up the coordinates of a point on an elliptic curve.


Syntax
------


IppStatus ippsGFpECSetPoint(const IppsGFpElement\* pX, const
IppsGFpElement\* pY, IppsGFpECPoint\* pPoint, IppsGFpECState\* pEC);


IppStatus ippsGFpECSetPointRegular(const IppsBigNumState\* pX, const
IppsBigNumState\* pY, IppsGFpECPoint\* pPoint, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pX, pY   
     - Pointers to the ``X`` and ``Y`` coordinates of the point on the elliptic curve.
   * - pPoint   
     - Pointer to the IppsGFpECPoint context.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function sets up the coordinates of a point on the elliptic curve
over the finite field.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the specified contexts does not match the operation.
   * - ippStsOutOfRangeErr   
     - Indicates an error if the point coordinates (pX, pY) do not belong to the finite field over which the elliptic curve is initialized.



