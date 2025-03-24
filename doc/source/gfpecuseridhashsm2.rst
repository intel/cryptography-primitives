.. _gfpecuseridhashsm2:

GFpECUserIDHashSM2
==================

Computes the hash value of the distinguished identifier of a user.

Syntax
-------

IppStatus ippsGFpECUserIDHashSM2, (Ipp8u * pZaDigest, const Ipp8u* pUserID, int userIDLen, const IppsGFpECPoint* pPublicKey,                                   IppsGFpECState* pEC, Ipp8u* pScratchBuffer)


Include Files
-------------

``ippcp.h``

Parameters 
----------


.. list-table:: 
   :header-rows: 0

   * - pZaDigest 
     - Pointer to the resulting digest Za.
   * - pUserID 
     - User ID data.
   * - userIDLen 
     - Length of user ID data.
   * - pMsg 
     - Pointer to the input message.
   * - pPublicKey 
     - Public key.
   * - pEC
     - Pointer to the elliptic curve context.
   * - pScratchBuffer
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize* for the elliptic curve.



Description
-----------

Computes the hash value of the distinguish identifier of a user Za = SM3( ENTL||ID||a||b||Gx||Gy||Px||Py).

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 2 to get the valid *pScratchBuffer*.


Return Values 
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers are NULL.
   * - ippStsContextMatchErr 
     - Indicates an error condition if the ``IppsGFpECState`` context parameter does not match the operation.
   * - ippStsNotSupportedModeErr
     - Indicates an error condition if the ``IppsGFpECState`` context parameter defines an elliptic curve over an extension of the prime finite field.
   * - ippStsOutOfRangeErr
     - Indicates an error condition if the invalid input argument range - inpLen < 0 or maxOutLen is not enough for the encryption.
   * - ippStsInvalidPoint
     - Indicates an error condition if pPublicKey is not on the curve.
   * - ippStsBadArgErr
     - Indicates an error condition if userIDLen value <= 0.
   * - ippStsOutOfRangeErr
     - Indicates an error condition if userIDLen value is less or equal to zero or public key length is out of range.
