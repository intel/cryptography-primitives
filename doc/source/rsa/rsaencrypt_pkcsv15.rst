.. _rsaencrypt_pkcsv15:



RSAEncrypt_PKCSv15
==================


Performs RSA-OAEP encryption using the RSA-OAEP scheme as defined in the
v1.5 version of the PKCS#1 standard (deprecated).


Syntax
------


IppStatus ippsRSAEncrypt_PKCSv15 (const Ipp8u\* pSrc, int srcLen, const
Ipp8u\* pRandPS, Ipp8u\* pDst, const IppsRSAPublicKeyState\* pKey,
Ipp8u\* pBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrc   
     -  Pointer to the input octet message to be encrypted.
   * -     srcLen   
     -  Length (in bytes) of the message. The message can be empty, that is, srcLen==0.
   * -     pRandPS   
     -  Pointer to the non-zero octet padding string. pRandPS can be NULL. In this case, the function applies the padding string of 0xFF bytes.
   * -     pDst   
     -  Pointer to the output message.
   * -     pKey   
     -  Pointer to the properly initialized IppsRSAPublicKeyState context.
   * -     pBuffer   
     -  Pointer to a buffer of size not less than returned by the :ref:`RSA_GetBufferSizePublicKey <rsa_getbuffersizepublickey-privatekey>` function.




Description
-----------


.. note::


   This algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: RSA-OAEP.


The function performs encryption using the RSA-OAEP scheme according to
the v1.5 version of the PKCS#1 standard, defined in :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`. The
length of the encrypted message is equal to size of the RSA modulus
``n``.


If RSAEncrypt_PKCSv15 receives a non-zero pRandPS pointer, the function
assumes that the length of the padding string is at least ``k``-srcLen-3
bytes, where ``k`` is the length of the RSA modulus in bytes.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   The v1.5 version of the PKCS#1 standard requires that you provide a
   padding string that does not contain zero bytes. If the padding
   string contains a zero byte, the encryption operation completes
   successfully, but the inverse decryption fails.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers other than pRandPS is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the RSA context parameter does not match the operation.
   * -     ippStsIncompleteContextErr   
     -     Indicates an error condition if the public key is not set up.   
   * -     ippStsSizeErr   
     -  Indicates an error condition if any input/output length parameters are inconsistent with one another.


.. note:: You can set up the public key in a call to ``RSA_SetPublicKey``.


.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsadecrypt_pkcsv15`
