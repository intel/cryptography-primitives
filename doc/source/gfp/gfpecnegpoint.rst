.. _gfpecnegpoint:


GFpECNegPoint
=============


Computes the inverse of a point.


Syntax
------


IppStatus ippsGFpECNegPoint(const IppsGFpECPoint\* pP, IppsGFpECPoint\*
pR, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pP   
     - Pointer to the context of the given point on the elliptic curve.
   * - pR   
     - Pointer to the context of the resulting point on the elliptic curve.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


For a given point of the elliptic curve over the finite field, this
function computes the coordinates of the inverse point. The following
pseudocode represents this operation: ``R = 0 - P``.


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



