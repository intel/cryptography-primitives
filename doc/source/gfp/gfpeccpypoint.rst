.. _gfpeccpypoint:

GFpECCpyPoint
=============


Copies one point to another.


Syntax
------


IppStatus ippsGFpECCpyPoint(const IppsGFpECPoint\* pA, IppsGFpECPoint\*
pR, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pA   
     - Pointer to the context of the elliptic curve point being copied.
   * - pR   
     - Pointer to the context of the elliptic curve point being changed.
   * - pEC   
     - Pointer to the context of the elliptic curve.




Description
-----------


This function copies one point of the elliptic curve over the finite
field to another.


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



