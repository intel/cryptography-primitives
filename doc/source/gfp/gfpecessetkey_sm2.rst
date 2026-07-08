.. _gfpecessetkey_sm2:

GFpECESSetKey_SM2
=================


Computes a shared secret.


Syntax
------


IppStatus ippsGFpECESSetKey_SM2(const IppsBigNumState\* pPrivate, const
IppsGFpECPoint\* pPublic, IppsECES_StateSM2\* pState, IppsGFpECState\*
pEC, Ipps8u\* pEcScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pEC
     - Pointer to the elliptic curve context used in the ECES.
   * - pState
     - Pointer to the buffer being initialized as the ECES context.
   * - pPrivate
     - Pointer to the own private keys of the elliptic curve.
   * - pPublic
     - Pointer to the patry public key of the elliptic curve.
   * - pEcScratchBuffer
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize* for the elliptic curve.




Description
-----------


The function computes a shared secret **Z** = [**Private**]\* **Public**
for future use.

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 1 to get the valid *pEcScratchBuffer*.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr
     - Indicates an error condition if the IppsGFpECState, IppsECES_StateSM2, IppsBigNumState,
       or IppsGFpECPoint context parameter does not match the operation.
   * - ippStsOutOfRangeErr
     - Indicates an error conditions in the following cases:

       * Any of the specified pointers does not belong to the finite field over that the elliptic curve is initialized.
       * The scalar values does not belong to the finite field over that the elliptic curve is initialized.

   * - ippStsNotSupportedModeErr
     - Indicates an error condition if the IppsGFpECState context parameter
       defines an elliptic curve over an extension of the prime finite field.
   * - ippStsBadArgErr
     - Indicates an error condition if the IppsGFpECState context parameter
       has an element size that differs from the one used in the
       :ref:`ippsGFpECESInit_SM2 <gfpecesinit_sm2>` function call.
   * - ippStsInvalidPoint
     - Indicates an error condition if the public key point pPublic does not belong to the elliptic curve.
   * - ippStsPointAtInfinity
     - Indicates an error condition if the IppsGFpECPoint context parameter defines a point at infinity.



