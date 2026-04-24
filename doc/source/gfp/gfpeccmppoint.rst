.. _gfpeccmppoint:


GFpECCmpPoint
=============


Compares two points.


Syntax
------


IppStatus ippsGFpECCmpPoint(const IppsGFpECPoint\* pP, const
IppsGFpECPoint\* pQ, IppECResult\* pResult, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``

Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the context of the first elliptic curve point.
   * - pQ   
     - Pointer to the context of the second elliptic curve point.
   * - pResult   
     - Pointer to the result of the comparison.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function compares the coordinates of two points on the elliptic
curve over the finite field and returns the result in pResult. The
result of the comparison may have the following values:


.. list-table:: 
   :header-rows: 0

   * - ippECPointIsEqual   
     - The points are equal.   
   * - ippECPointIsNotEqual   
     - The points are not equal.   




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
     - Indicates an error condition if any of the points does not belong to the finite field over which the elliptic curve is initialized.



