.. _gfpectstpoint:

GFpECTstPoint
=============


Checks if a point belongs to an elliptic curve.


Syntax
------


IppStatus ippsGFpECTstPoint(const IppsGFpECPoint\* pP, IppECResult\*
pResult, IppsGFpECState\* pEC);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pP   
     -  Pointer to the IppsGFpECPoint context.
   * -     pResult   
     -  Pointer to the result of the check.
   * -     pEC   
     -  Pointer to the context of the elliptic curve.




Description
-----------


This function checks whether the given point belongs to the elliptic
curve over the finite field. The result of the testing is returned
in ``pResult`` and may have the following values:


.. list-table:: 
   :header-rows: 0

   * -     ippECValid   
     -     The point belongs to the curve.   
   * -     ippECPointIsAtInfinite   
     -     The point is a point at infinity.   
   * -     ippECPointIsNotValid   
     -     The point does not belong to the curve.   




Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the specified contexts does not match the operation.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if the coordinates of the point pP do not belong to the finite field over which the elliptic curve is initialized.



