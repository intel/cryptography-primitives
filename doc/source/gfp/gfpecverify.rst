.. _gfpecverify:


GFpECVerify
===========


Verifies the parameters of an elliptic curve.


Syntax
------


IppStatus ippsGFpECVerify(IppECResult\* pResult, IppsGFpECState\* pEC,
Ipp8u\* pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pResult   
     -  Pointer to the verification result.
   * -     pEC   
     -  Pointer to the context of the elliptic curve.
   * -     pScratchBuffer   
     -  Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.





Description
-----------


This function verifies the parameters of the elliptic curve from the
input ``IppsGFpECState`` context and returns the result in ``pResult``. The
result of the verification may have the following values:

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 2 to get the valid *pScratchBuffer*.


.. list-table:: 
   :header-rows: 0

   * -     ippECValid   
     -     Parameters are valid.   
   * -     ippECIsZeroDiscriminant   
     -     \ ``4 ⋅ A``\ :sup:`3`\ ``+ 3 ⋅ B``\ :sup:`2`\ ``= 0``.   
   * -     ippECPointIsAtInfinity   
     -     Base point ``G = (x, y)`` is a point at infinity.   
   * -     ippECPointIsNotValid   
     -     Base point ``G = (x, y)`` does not belong to the curve.   
   * -     ippECInvalidOrder   
     -     Order of the base point ``G = (x, y)`` is invalid.   


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the IppsGFpECState context parameter does not match the operation.



