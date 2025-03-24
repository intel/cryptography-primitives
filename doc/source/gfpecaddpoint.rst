.. _gfpecaddpoint:



GFpECAddPoint
=============


Computes the sum of two points on an elliptic curve.


Syntax
------


IppStatus ippsGFpECAddPoint(const IppsGFpECPoint\* pP, const
IppsGFpECPoint\* pQ, IppsGFpECPoint\* pR, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the context of the first point on the elliptic curve to be added.
   * - pQ   
     - Pointer to the context of the second point on the elliptic curve to be added.
   * - pR   
     - Pointer to the context of the resulting point on the elliptic curve.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function computes the coordinates of the elliptic curve point that
is equal to the sum of two given points. The following pseudocode
represents this operation: ``R = P + Q``.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the specified contexts does not match the operation.
   * - ippStsOutOfRangeErr   
     - Indicates an error condition if any of the specified points does not belong to the finite field over which the elliptic curve is initialized.



