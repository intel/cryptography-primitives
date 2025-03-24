.. _gfpecgetpoint-gfpecgetpointregular:


GFpECGetPoint , GFpECGetPointRegular
====================================


Retrieves coordinates of a point on an elliptic curve.


Syntax
------


IppStatus ippsGFpECGetPoint(const IppsGFpECPoint\* pPoint,
IppsGFpElement\* pX, IppsGFpElement\* pY, IppsGFpECState\* pEC);


IppStatus ippsGFpECGetPointRegular(const IppsGFpECPoint\* pPoint,
IppsBigNumState\* pX, IppsBigNumState\* pY, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pPoint   
     - Pointer to the IppsGFpECPoint context.
   * - pX, pY   
     - Pointers to the ``X`` and ``Y`` coordinates of a point on the elliptic curve.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function exports the coordinates of an elliptic curve point from
the IppsGFPECPoint context to the user-defined elements of the
underlying field. To turn off the extraction of a particular coordinate,
set the appropriate function parameter to NULL.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if pPoint or pEC is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the specified contexts does not match the operation.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition in the following cases:
     
       * The coordinates of the point pPoint do not belong to the underlying finite field of the elliptic curve.
       * pX or pY does not belong to the underlying finite field of the elliptic curve.




