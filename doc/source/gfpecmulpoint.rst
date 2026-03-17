.. _gfpecmulpoint:


GFpECMulPoint
=============


Multiplies a point on an elliptic curve by a scalar.


Syntax
------


IppStatus ippsGFpECMulPoint(const IppsGFpECPoint\* pP, const
IppsBigNumState\* pN, IppsGFpECPoint\* pR, IppsGFpECState\* pEC, Ipp8u\*
pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pP   
     - Pointer to the context of the given point on the elliptic curve.
   * - pN   
     - Pointer to the Big Number context storing the scalar value.
   * - pR   
     - Pointer to the context of the resulting point on the elliptic curve.
   * - pEC   
     - Pointer to the context of the elliptic curve.
   * - pScratchBuffer   
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


This function computes the coordinates of the elliptic curve point that
equals the product of the given point and a scalar. The following
pseudocode represents this operation: ``R = scalar ⋅ P``.

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 1 to get the valid *pScratchBuffer*.

.. note::
   Note: The point multiplication kernel implementation ensures all intermediate values remain in registers, avoiding memory spills to the stack.

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
     
       * Any of the points does not belong to the finite field over which the elliptic curve is initialized.
       * The scalar value does not belong to the finite field over which the elliptic curve is initialized.



