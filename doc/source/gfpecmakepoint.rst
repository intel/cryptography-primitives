.. _gfpecmakepoint:


GFpECMakePoint
==============


Constructs the coordinates of a point on an elliptic curve based on the
X-coordinate.


Syntax
------


IppStatus ippsGFpECMakePoint(const IppsGFpElement\* pX, IppsGFpECPoint\*
pPoint, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pX   
     - Pointer to the ``X``-coordinate of the point on the elliptic curve.
   * - pPoint   
     - Pointer to the IppsGFpECPoint context.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function computes the coordinates of a point on an elliptic curve
based on the ``X``-coordinate.


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
     - Indicates an error condition in the following cases:
       
       * The coordinates of the point pPoint do not belong to the finite field over which the elliptic curve is initialized.
       * The point coordinate pX does not belong to the finite field over which the elliptic curve is initialized.
       
   * - ippStsBadArgErr   
     - Indicates an error condition if the finite field over which the elliptic curve is initialized is not prime.
   * - ippStsQuadraticNonResidueErr   
     - Indicates an error condition if the square of the ``Y``-coordinate of the point is a quadratic non-residue modulo ``p``.



