.. _gfpecmessagerepresentationsm2:


GFpECMessageRepresentationSM2
=============================

Computes the SM2 digest of a message.

Syntax
-------

IppStatus ippsGFpECMessageRepresentationSM2, (IppsBigNumState * pMsgDigest, const Ipp8u * pMsg, int msgLen, const Ipp8u * pUserID, int userIDLen,                       const IppsGFpECPoint * pRegPublic, IppsGFpECState * pEC, Ipp8u * pScratchBuffer)
 

Include Files
-------------

``ippcp.h``

Parameters 
----------


.. list-table:: 
   :header-rows: 0

   * - pMsgDigest 
     - Pointer to the resulting message digest.
   * - pMsg  
     - Pointer to the input message.
   * - msgLen 
     - Length of the input message.
   * - pUserID 
     - User ID data.
   * - userIDLen 
     - Length of user ID data.
   * - pMsg 
     - Pointer to the input message.
   * - pRegPublic 
     - Public key.
   * - pEC
     - Pointer to the elliptic curve context.
   * - pScratchBuffer
     - Pointer to the scratch buffer for the elliptic curve.


Description
-----------

The function compresses message M', including Za and M, using a cryptographic hash function before the signature process. Therefore, do the first two steps of the algorithm that helps obtain a signature (r, s).

GM/T 0003.2-2012. Public Key cryptographic algorithm SM2 based on the elliptic curves.

Part 2: Digital signature algorithm 

6.1 Digital signature generation algorithm

A1: compute Za = SM3( ENTL || ID || a || b || xG || yG || xA || yA )

A2: e = SM3(Za || M)


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
   * - ippStsMessageErr
     - Indicates an error condition if bitsize(pMsgDigest) > bitsize(order).
   * - ippStsNotSupportedModeErr
     - Indicates an error condition if the ``IppsGFpECState`` context parameter defines an elliptic curve over an extension of the prime finite field.

