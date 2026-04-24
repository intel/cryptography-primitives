.. _gfpeckeyexchangesm2_setup:

GFpECKeyExchangeSM2_Setup
=========================

Set up the ``IppsGFpECKeyExchangeSM2State`` context for further operation of the SM2 Key Exchange algorithm.

Syntax
-------

IppStatus ippsGFpECKeyExchangeSM2_Setup(const Ipp8u pZSelf[IPP_SM3_DIGEST_BYTESIZE], const Ipp8u pZPeer[IPP_SM3_DIGEST_BYTESIZE],                                     const IppsGFpECPoint * pPublicKeySelf, const IppsGFpECPoint * pPublicKeyPeer, const IppsGFpECPoint * pEphPublicKeySelf, const IppsGFpECPoint * pEphPublicKeyPeer, psGFpECKeyExchangeSM2State * pKE)



Include Files
-------------

``ippcp.h``

Parameters 
----------


.. list-table:: 
   :header-rows: 0

   * - pZSelf
     - Pointer to the Self-User ID Hash. 
   * - pZPeer
     - Pointer to the Peer-User ID Hash.
   * - pPublicKeySelf
     - Pointer to the Self-public key of the elliptic curve.
   * - pPublicKeyPeer
     - Pointer to the Peer-public key of the elliptic curve.
   * - pEphPublicKeySelf
     - Ephemeral pointer to the Self-public key of the elliptic curve.
   * - pEphPublicKeyPeer
     - Ephemeral pointer to the Peer-public key of the elliptic curve. 
   * - pKE
     - Pointer to the buffer begging initialization.


Description
-----------

Set up public/public ephemeral keys and User ID Hash to the ``IppsGFpECKeyExchangeSM2State`` context for further operation of the SM2 Key Exchange scheme.


Return Values 
-------------

.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers are NULL.
   * - ippStsContextMatchErr 
     - Indicates an error condition if the ``IppsGFpECState`` context parameter does not match the operation or public keys are set up incorrectly.
   * - ippStsNotSupportedModeErr
     - Indicates an error condition if the ``IppsGFpECState`` context parameter defines an elliptic curve over an extension of the prime finite field.
   * - ippStsRangeErr
     - Indicates an error condition if the length in bits of the elliptic curve is less than the length in bits of the SM3 hash digest.
   * - ippStsBadArgErr
     - Indicates an error condition if the role is not equal to ``ippKESM2Requester`` or ``ippKESM2Responder``.
   * - ippStsInvalidPoint
     - Indicates an error condition if the point of the elliptic curve does not belong to the elliptic curve. 
   * - ippStsOutOfRangeErr
     - Indicates an error condition if public key lengths are out of range.
