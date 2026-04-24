.. _gfpeckeyexchangesm2_init:

GFpECKeyExchangeSM2_Init
========================

Initializes the SM2 Key Exchange Elliptic Curve context. 

Syntax
-------

IppStatus ippsGFpECKeyExchangeSM2_Init (IppsGFpECKeyExchangeSM2State* pKE, IppsKeyExchangeRoleSM2 role, IppsGFpECState* pEC)


Include Files
-------------

``ippcp.h``

Parameters 
----------


.. list-table:: 
   :header-rows: 0

   * - pKE
     - Pointer to the buffer begging initialization.
   * - role
     - Role in SM2 key exchange Requester (User A)/Responder(User B) - ippKESM2Requester/ ippKESM2Responder.
   * - pEC
     - Pointer to the elliptic curve context.




Description
-----------

The function initializes the memory buffer pointed to by pKE as ``IppsGFpECKeyExchangeSM2State``.


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
     - Indicates an error condition if the length in bits of the elliptic curve is less than the length in bits of the SM3 hash digest..
   * - ippStsBadArgErr
     - Indicates an error condition if the role is not equal to ``ippKESM2Requester`` or ``ippKESM2Responder``.

