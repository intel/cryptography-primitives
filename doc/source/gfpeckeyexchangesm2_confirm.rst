.. _gfpeckeyexchangesm2_confirm:

GFpECKeyExchangeSM2_Confirm
===========================

(Optional) Verification of the legality of the second party.

Syntax
-------

IppStatus ippsGFpECKeyExchangeSM2_Confirm(const Ipp8u pSPeer[IPP_SM3_DIGEST_BYTESIZE], int* pStatus, IppsGFpECKeyExchangeSM2State* pKE)


Include Files
-------------

``ippcp.h``

Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSPeer
     - Pointer to the Peer Conformation hash data.
   * - pStatus
     - Pointer to the result of the verification of the confirmation of the second party.
   * - pKE
     - Pointer to the buffer as the ``IppsGFpECKeyExchangeSM2State`` context.


Description
-----------

(Optional) [GBT.32918.3-2016] Public Key cryptographic algorithm SM2 based on the elliptic curves.

Part 3: Key exchange protocol

6.2 Process of key exchange protocol

stack compute[standard link]:

.. list-table::
   :header-rows: 0

   * -
     - [user  A| user  B]
   * - 8) S(1/2) = SM3( 0x0(2/3) || y(u/v) || tmp_p
     - [step  9| step 10]

where tmp_p - precompute in SharedKey step on of the legality of the second party SM2 Key Exchange scheme.

The result of checking the legitimacy of the second party is one of two possible values:

* 1, successful
* 0, bad confirmation




Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or a warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers are NULL.
   * - ippStsContextMatchErr
     - Indicates an error condition if the ``IppsGFpECState`` context parameter inside ``IppsGFpECKeyExchangeSM2State`` does not match the operationy.
   * - ippStsNotSupportedModeErr
     - Indicates an error condition if the ``IppsGFpECState`` context parameter inside  ``IppsGFpECKeyExchangeSM2State`` defines an elliptic curve over an extension of the prime finite field.
   * - ippStsRangeErr
     - Indicates an error condition if the length in bits of the elliptic curve is less than the length in bits of the SM3 hash digest.
   * - ippStsBadArgErr
     - Indicates an error condition if the role is not equal to ``ippKESM2Requester`` or ``ippKESM2Responder``.

