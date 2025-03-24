.. _gfpecpsigndsa-gfpecpsignnr-gfpecpsignsm2:

GFpECPSignDSA, GFpECPSignNR, GFpECPSignSM2
==========================================


Computes a digital signature over a message digest.


Syntax
------


IppStatus ippsGFpECSignDSA(const IppsBigNumState\* pMsgDigest, const
IppsBigNumState\* pRegPrivate, const IppsBigNumState\* pEphPrivate,
IppsBigNumState\* pSignR, IppsBigNumState\* pSignS, IppsGFpECState\*
pEC, Ipp8u\* pScratchBuffer);


IppStatus ippsGFpECSignNR(const IppsBigNumState\* pMsgDigest, const
IppsBigNumState\* pRegPrivate, const IppsBigNumState\* pEphPrivate,
IppsBigNumState\* pSignR, IppsBigNumState\* pSignS, IppsGFpECState\*
pEC, Ipp8u\* pScratchBuffer);


IppStatus ippsGFpECSignSM2(const IppsBigNumState\* pMsgDigest, const
IppsBigNumState\* pRegPrivate, const IppsBigNumState\* pEphPrivate,
IppsBigNumState\* pSignR, IppsBigNumState\* pSignS, IppsGFpECState\*
pEC, Ipp8u\* pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pMsgDigest
     - Pointer to the message digest *msg* to be digitally signed, that is, to be ecrypted with a private key.
   * - pRegPrivate
     - Pointer to the regular private key of the signer.
   * - pEphPrivate
     - Pointer to the ephemeral private key of the signer.
   * - pSignR
     - Pointer to the integer ``r`` of the digital signature.
   * - pSignS
     - Pointer to the integer ``s`` of the digital signature.
   * - pEC
     - Pointer to the context of the elliptic curve.
   * - pScratchBuffer
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


Functions generate a digital signature respectively to DSA :term:`IEEE P1363A <[IEEE P1363A]>`,
Nyberg-Rueppel :term:`IEEE P1363A <[IEEE P1363A]>` and SM2
:term:`SM2 <[SM2]>` schemes.

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
     - Indicates an error condition if any of the contexts pointed to by pMsgDigest, pRegPrivate, pEphPrivate, pSignR, pSignS, or pEC does not match the operation.
   * - ippStsMessageErr
     - Indicates an error condition if the value of ``msg`` pointed to by pMsgDigest falls outside the range of [1, ``n``-1], where ``n`` is the order of the elliptic curve base point ``G``.
   * - ippStsRangeErr
     - Indicates an error condition if any of the parameters pointed to by pSignR or pSignS has memory size that is smaller than the order ``n`` of the elliptic curve base point ``G``.
   * - ippStsIvalidPrivateKey
     - Indicates an error condition if any of the parameters pointed to by pRegPrivate or pEphPrivate has memory size that is smaller than the order ``n`` of the elliptic curve base point ``G``.
   * - ippStsNotSupportedModeErr
     - Indicates an error condition if the finite field GFp under the elliptic curve is not prime.
   * - ippStsEphemeralKeyErr
     - Indicates an error condition if values of the ephemeral keys ``ephPrivKey`` and ``ephPubKey`` are not valid: the digital signature calculation returns ``r``\ =0 or ``s``\ =0 as a result.



