.. _rsasign_pss:

RSASign_PSS
===========


Carries out the RSASSA-PSS signature generation scheme.


Syntax
------


IppStatus ippsRSASign_PSS(const Ipp8u\* pMsg, int msgLen, const Ipp8u\*
pSalt, int saltLen, Ipp8u\* pSign, const IppsRSAPrivateKeyState\*
pPrivateKey, const IppsRSAPublicKeyState\* pPublicKeyOpt, IppHashAlgId
hashAlg, Ipp8u\* pBuffer);


IppStatus ippsRSASign_PSS_rmf(const Ipp8u\* pMsg, int msgLen, const
Ipp8u\* pSalt, int saltLen, Ipp8u\* pSign, const
IppsRSAPrivateKeyState\* pPrivateKey, const IppsRSAPublicKeyState\*
pPublicKeyOpt, const IppsHashMethod\* pMethod, Ipp8u\* pBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pMsg
     -  Pointer to the octet message to be signed.
   * -     msgLen
     -  Length of the input \*pMsg message in octets.
   * -     pSalt
     -  Pointer to the random octet salt string.
   * -     saltLen
     -  Length of the salt string in octets.
   * -     pSign
     -  Pointer to the output octet signature.
   * -     pPrivateKey
     -  Pointer to the properly initialized IppsRSAPrivateKeyState context.
   * -     pPublicKeyOpt
     -  Pointer to the properly initialized optional IppsRSAPublicKeyState context.
   * -     hashAlg
     -  Identifier of the hash algorithm. For details, see table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
   * -     pMethod
     -  Pointer to the hash method. For details, see :ref:`HashMethod <hashmethod>` functions.
   * -     pBuffer
     -  Pointer to a temporary buffer of size not less than returned by each of the functions :ref:`RSA_GetBufferSizePrivateKey and RSA_GetBufferSizePublicKeyKey <rsa_getbuffersizepublickey-privatekey>`.




Description
-----------

.. note::


   ippsRSASign_PSS API is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The function generates the message signature according to the RSASSA-PSS
scheme defined in :term:`PKCS 1.2.1 <[PKCS 1.2.1]>` using
the hash algorithm defined by the hashAlg or pMethod parameter.


If you are using an RSA private key type 2 to generate the signature,
you can use the optional \*pPublicKeyOpt parameter to mitigate Fault
Attack. If you are using an RSA private key type 1 or sure that Fault
Attack is not applicable, pPublicKeyOpt can be NULL. Passing the NULL
value to the pPublicKeyOpt parameter saves computation time.


.. note::


   This function has a *reduced memory footprint* version. To learn
   more, see :ref:`Reduced Memory Footprint Functions <one-way-hash-primitives>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -      Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -     Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr
     -     Indicates an error condition if any of the context parameters does not match the operation.
   * -     ippStsIncompleteContextErr
     -     Indicates an error condition if the public or private key is not set up.
   * -     ippStsLengthErr
     -     Indicates an error condition if the value of saltLen is negative or any input/output length parameters are inconsistent with one another together (see [PKCS 1.2.1] for details).
   * -     ippsStsNotSupportedModeErr
     -      Indicates an error condition if the hashAlg parameter does not match any value of IppHashAlgId listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.



.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsa_generatekeys`
* :ref:`rsasign_pss`
