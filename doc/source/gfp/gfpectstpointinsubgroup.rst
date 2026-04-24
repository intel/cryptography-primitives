.. _gfpectstpointinsubgroup:


GFpECTstPointInSubgroup
=======================


Checks if a point belongs to a specified subgroup.


Syntax
------


IppStatus ippsGFpECTstPointInSubgroup(const IppsGFpECPoint\* pP,
IppECResult\* pResult, IppsGFpECState\* pEC, Ipp8u\* pScratchBuffer);


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
     -  Pointer to the result received upon the check that the point belongs to the elliptic curve over the finite field.
   * -     pEC   
     -  Pointer to the context of the elliptic curve.
   * -     pScratchBuffer   
     -  Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


This function checks whether a point belongs to the pre-defined subgroup
of the elliptic curve defined over the finite field. The result of the
testing is returned in ``pResult`` and may have the following values:


.. list-table:: 
   :header-rows: 0

   * -     ippECValid   
     -     The point is in the subgroup of the curve.   
   * -     ippECPointOutOfGroup   
     -     The point is out of the subgroup.   


The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 1 to get the valid *pScratchBuffer*.



Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the pointers pP, pResult, and pEC is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if any of the specified contexts does not match the operation.
   * -     ippStsOutOfRangeErr   
     -  Indicates an error condition if the point does not belong to the finite field over which the elliptic curve is initialized.



