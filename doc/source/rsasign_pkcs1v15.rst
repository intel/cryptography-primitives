.. _rsasign_pkcs1v15:


RSASign_PKCS1v15
================


*Carries out the RSA-SSA signature generation* scheme of *PKCS#1 v1.5* .


Syntax
------


IppStatus ippsRSASign_PKCS1v15(const Ipp8u\* pMsg, int msgLen, Ipp8u\*
pSign, const IppsRSAPrivateKeyState\* pPrivateKey, const
IppsRSAPublicKeyState\* pPublicKeyOpt, IppHashAlgId hashAlg, Ipp8u\*
pBuffer);


IppStatus ippsRSASign_PKCS1v15_rmf(const Ipp8u\* pMsg, int msgLen,
Ipp8u\* pSign, const IppsRSAPrivateKeyState\* pPrivateKey, const
IppsRSAPublicKeyState\* pPublicKeyOpt, const IppsHashMethod\* pMethod,
Ipp8u\* pBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pMsg
     -  Pointer to the message to be signed.
   * -     msgLen
     -  Length of the message \*pMsg in octets.
   * -     pSign
     -  Pointer to the output octet signature.
   * -     pPrivateKey
     -  Pointer to the properly initialized IppsRSAPrivateKeyState context.
   * -     pPublicKeyOpt
     -  Pointer to the properly initialized optional IppsRSAPublicKeyState context.
   * -     hashAlg
     -  Identifier of the hash algorithm used. For details, see table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
   * -     pMethod
     -  Pointer to the hash method. For details, see :ref:`HashMethod <hashmethod>` functions.
   * -     pBuffer
     -  Pointer to a temporary buffer of size not less than returned by each of the functions :ref:`RSA_GetBufferSizePrivateKey and RSA_GetBufferSizePublicKeyKey <rsa_getbuffersizepublickey-privatekey>`.




Description
-----------

.. note::


   ippsRSASign_PKCS1v15 API is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The function computes the messagedigest specified by the hashAlg or
pMethod parameter and generates thesignature according to the
RSASSA-PKCS1-v1_5 scheme defined in :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`.


If you are using an RSA private key type 2 to generate the signature,
you can use the optional \*pPublicKeyOpt parameter to mitigate Fault
Attack. If you are using an RSA private key type 1 or sure that Fault
Attack is not applicable, pPublicKeyOpt can be NULL. Passing the NULL
value to the pPublicKeyOpt parameter saves computation time.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   The length of the signature being generated equals the length of the
   RSA modulus, supplied with the IppsRSAPrivateKeyState context. Make
   sure that pSign points to a buffer of a sufficient length.


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
     -     Indicates an error condition if any input/output length parameters are inconsistent with one another.
   * -     ippStsSizeErr
     -     Indicates an error condition if the length of the RSA modulus is too small (see details in :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`.
   * -     ippStsNotSupportedModeErr
     -      Indicates an error condition if the hashAlg parameter does not match any value of IppHashAlgId listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.


.. note:: While you can set up the public key or type 1 private key in a call to ``RSA_SetPublicKey`` or ``RSA_SetPrivateKeyType1``, respectively, you can set up the type 2 private key in a call to either ``RSA_SetPrivateKeyType2`` or ``RSA_GenerateKeys``.



.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsa_generatekeys`
* :ref:`rsaverify_pkcs1v15`
