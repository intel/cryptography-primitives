.. _rsadecrypt_oaep:


RSADecrypt_OAEP
===============


Carries out the RSA-OAEP decryption scheme.


Syntax
------


IppStatus ippsRSADecrypt_OAEP(const Ipp8u\* pSrc, const Ipp8u\* pLabel,
int labLen, Ipp8u\* pDst, int\* pDstLen, const IppsRSAPrivateKeyState\*
pKey, IppHashAlgId hashAlg, Ipp8u\* pBuffer);


IppStatus ippsRSADecrypt_OAEP_rmf(const Ipp8u\* pSrc, const Ipp8u\*
pLabel, int labLen, Ipp8u\* pDst, int\* pDstLen, const
IppsRSAPrivateKeyState\* pKey, const IppsHashMethod\* pMethod, Ipp8u\*
pBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pSrc
     -  Pointer to the octet ciphertext to be decrypted.
   * -     pLabel
     -  Pointer to the optional label to be associated with the message.
   * -     labLen
     -  Length of the optional label.
   * -     pDst
     -  Pointer to the output octet plaintext message.
   * -     pDstLen
     -  Pointer to the length of the decrypted message.
   * -     pKey
     -  Pointer to the properly initialized IppsRSAPrivateKeyState context.
   * -     hashAlg
     -  ID of the hash algorithm used. For details, see table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
   * -     pMethod
     -  Pointer to the hash method. For details, see :ref:`HashMethod <hashmethod>` functions.
   * -     pBuffer
     -  Pointer to a temporary buffer of size not less than returned by the :ref:`RSA_GetBufferSizePrivateKey <rsa_getbuffersizepublickey-privatekey>` function.




Description
-----------

.. note::


   ippsRSADecrypt_OAEP API is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.


The function carries out the RSA-OAEP decryption scheme defined in
:term:`PKCS 1.2.1 <[PKCS 1.2.1]>`.
The \*pDstLen parameter returns the length of the decrypted message.


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
     -      Indicates an error condition if the private key is not set up.
   * -     ippStsLengthErr
     -  Indicates an error condition if the any input/output length parameters are inconsistent with one another.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if the hashAlg parameter does not match any value of IppHashAlgId listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.


.. note:: While you can set up the type 1 private key in a call to ``RSA_SetPrivateKeyType1``, you can set up the type 2 private key in a call to either ``RSA_SetPrivateKeyType2`` or ``RSA_GenerateKeys``.


.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsaencrypt_oaep`
* :ref:`rsa_generatekeys`

