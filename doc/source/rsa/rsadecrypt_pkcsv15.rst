.. _rsadecrypt_pkcsv15:



RSADecrypt_PKCSv15
==================


Performs RSA-OAEP decryption using the RSA-OAEP scheme as defined in the
v1.5 version of the PKCS#1 standard (deprecated).


Syntax
------


IppStatus ippsRSADecrypt_PKCSv15 (const Ipp8u\* pSrc, Ipp8u\* pDst,
int\* pDstLen, const IppsRSAPrivateKeyState\* pKey, Ipp8u\* pBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrc   
     -  Pointer to the input octet message to be decrypted.
   * -     pDst
     -  Pointer to the output message. The buffer must be at least the size of the RSA modulus in bytes (see the note below).
   * -     pDstLen   
     -  Pointer to the length (in bytes) of the decrypted message.
   * -     pKey   
     -  Pointer to the properly initialized IppsRSAPrivateKeyState context.
   * -     pBuffer   
     -  Pointer to a temporary buffer of size not less than returned by the :ref:`RSA_GetBufferSizePrivateKey <rsa_getbuffersizepublickey-privatekey>` function.




Description
-----------


.. note::


   This algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: RSA-OAEP.


The function performs decryption using the RSA-OAEP scheme according to
the v1.5 version of the PKCS#1 standard, defined in :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`. The
\*pDstLen parameter returns the length of the decrypted message.


.. note::


   If an empty message is encrypted by the RSAEncrypt_PKCSv15 function,
   RSADecrypt_PKCSv15 returns and empty string, that is, \*pDstLen==0.


.. note::


   To avoid leaking the message length through memory-access patterns, the
   function writes the full RSA modulus size to ``pDst`` regardless of the
   decrypted message length. The application must therefore provide a ``pDst``
   buffer of at least the RSA modulus size in bytes, and use \*pDstLen to
   determine the number of valid message bytes.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr   
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr   
     -  Indicates an error condition if the RSA context parameter does not match the operation.
   * -     ippStsIncompleteContextErr   
     -      Indicates an error condition if the private key is not set up.   
   * -     ippStsSizeErr   
     -  Indicates an error condition if any input/output length parameters are inconsistent with one another.


.. note:: While you can set up the type 1 private key in a call to ``RSA_SetPrivateKeyType1``, you can set up the type 2 private key in a call to either ``RSA_SetPrivateKeyType2`` or ``RSA_GenerateKeys``.
          
          
 .. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsa_generatekeys`
* :ref:`rsaencrypt_pkcsv15`
