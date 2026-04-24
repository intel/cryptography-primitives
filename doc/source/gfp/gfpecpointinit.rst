.. _gfpecpointinit:

GFpECPointInit
==============


Initializes the context of a point on an elliptic curve.


Syntax
------


IppStatus ippsGFpECPointInit(const IppsGFpElement\* pX, const
IppsGFpElement\* pY, IppsGFpECPoint\* pPoint, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pX, pY   
     - Pointers to the ``X`` and ``Y`` coordinates of a point on the elliptic curve.
   * - pPoint   
     - Pointer to the IppsGFpECPoint context being initialized.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function initializes the IppsGFpECPoint context and sets the
coordinates of an elliptic curve point to the values stored in pX and
pY. If any of the pointers to the ``X`` and ``Y`` coordinates is zero,
the function sets the coordinates of the elliptic curve point in the
IppsGFpECPoint context to the coordinates of a point at infinity.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if either pPoint or pEC is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition in the following cases:
       
       * ``IppsGFpECState`` context parameter does not match the operation.
       * Neither of the pointers to the X and Y coordinates is zero, and any of the corresponding context parameters does not match the operation.
       
   * - ippStsOutOfRangeErr   
     - Indicates an error if the point coordinates (pX, pY) do not belong to the finite field over which the elliptic curve is initialized.



