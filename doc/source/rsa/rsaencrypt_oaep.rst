.. _rsaencrypt_oaep:


RSAEncrypt_OAEP
===============


Carries out the RSA-OAEP encryption scheme.


Syntax
------


IppStatus ippsRSAEncrypt_OAEP(const Ipp8u\* pSrc, int srcLen, const
Ipp8u\* pLabel, int labLen, const Ipp8u\* pSeed, Ipp8u\* pDst, const
IppsRSAPublicKeyState\* pKey, IppHashAlgId hashAlg, Ipp8u\* pBuffer);


IppStatus ippsRSAEncrypt_OAEP_rmf(const Ipp8u\* pSrc, int srcLen, const
Ipp8u\* pLabel, int labLen, const Ipp8u\* pSeed, Ipp8u\* pDst, const
IppsRSAPublicKeyState\* pKey, const IppsHashMethod\* pMethod, Ipp8u\*
pBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pSrc
     -  Pointer to the octet message to be encrypted.
   * -     srcLen
     -  Length of the message to be encrypted.
   * -     pLabel
     -  Pointer to the optional label to be associated with the message.
   * -     labLen
     -  Length of the optional label.
   * -     pSeed
     -  Pointer to the random octet string of length ``hashLen``, where ``hashLen`` is the length (in octets) of the hash function output.
   * -     pDst
     -  Pointer to the output octet ciphertext string.
   * -     pKey
     -  Pointer to the properly initialized IppsRSAPublicKeyState context.
   * -     hashAlg
     -  ID of the hash algorithm used. For details, see table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
   * -     pMethod
     -  Pointer to the hash method. For details, see :ref:`HashMethod <hashmethod>` functions.
   * -     pBuffer
     -  Pointer to a temporary buffer of size not less than returned by the :ref:`RSA_GetBufferSizePublicKey <rsa_getbuffersizepublickey-privatekey>` function.




Description
-----------

.. note::


   ippsRSAEncrypt_OAEP API is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.


The function carries out the RSA-OAEP encryption scheme, defined in
:term:`PKCS 1.2.1 <[PKCS 1.2.1]>`.
The length of the encrypted message is equal to the size of the RSA
modulus ``n``.


.. note::


   This function has a *reduced memory footprint* version. To learn
   more, see :ref:`Reduced Memory Footprint Functions <one-way-hash-primitives>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr
     -  Indicates an error condition if the context parameter does not match the operation.
   * -     ippStsIncompleteContextErr
     -     Indicates an error condition if the public key is not set up.
   * -     ippStsLengthErr
     -  Indicates an error condition if the any input/output length parameters are inconsistent with one another.
   * -     ippStsNotSupportedModeErr
     -  if the hashAlg parameter does not match any value of IppHashAlgId listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.

.. note:: You can set up the public key in a call to RSA_SetPublicKey.


.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsadecrypt_oaep`

