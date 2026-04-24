.. _gfpecsetpointrandom:


GFpECSetPointRandom
===================


Sets the coordinates of a point on an elliptic curve to random values.


Syntax
------


IppStatus ippsGFpECSetPointRandom(IppsGFpECPoint\* pPoint,
IppsGFpECState\* pEC, IppBitSupplier rndFunc, void\* pRndParam, Ipp8u\*
pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pPoint   
     - Pointer to the IppsGFpECPoint context.
   * - pEC   
     - Pointer to the context of the elliptic curve.
   * - rndFunc   
     - Pesudorandom number generator.
   * - pRndParam   
     - Pointer to the pseudorandom number generator context.
   * - pScratchBuffer   
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


This function assigns random values to the coordinates of an elliptic
curve point in the IppsGFpECPoint context.

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 1 to get the valid *pScratchBuffer*.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the context parameters does not match the operation.
   * - ippStsOutOfRangeErr   
     - Indicates an error if the specified point does not belong to the finite field over which the elliptic curve is initialized.



