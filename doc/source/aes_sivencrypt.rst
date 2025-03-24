.. _aes_sivencrypt:



AES_SIVEncrypt
==============


Performs the SIV authenticated encryption using the AES cipher.


Syntax
------


IppStatus ippsAES_SIVEncrypt(const Ipp8u\* pSrc, Ipp8u\* pDst, int len,
Ipp8u\* pSIV, const Ipp8u\* pAuthKey, const Ipp8u\* pConfKey, int
keyLen, const Ipp8u\* AD[], const int ADlen[], int numAD);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc
     - Pointer to the input data to encrypt (plaintext).
   * - pDst
     - Pointer to the output encrypted data (ciphertext).
   * - len
     - Length in bytes of the plaintext and ciphertext.
   * - pSIV
     - Pointer to the output synthetic initialization vector.
   * - pAuthKey
     - Pointer to the authentication key.
   * - pConfKey
     - Pointer to the confidentiality key.
   * - keyLen
     - Length of keys in bytes.
   * - AD
     - Array of pointers to the associated input strings.
   * - ADlen
     - Array of length (in bytes) of the associated input strings.
   * - numAD
     - The number of the associated strings.




Description
-----------


The AES_SIVEncrypt function acceptsauthentication and confidentiality
keys of length keyLen each, plaintext (\*pSrc) of an arbitrarylength
len, and a vector AD[] of associated data(strings). The output of the
function is the 16-byte synthetic initialization vector (\*pSIV)
andencrypted data (\*pDst) of the same length as theplaintext.


The computation includes the following steps:


#. Compute a synthetic initialization vector by passing the plaintext,
   pAuthKey key, and AD[] to
   :ref:`AES_S2V_CMAC <aes_s2v_cmac>`.


#. Encrypt the plaintext using the AES cipher in the CTR mode with the
   initial counter value (``CTR0``) equal to the synthetic initialization
   vector xored with a fixed mask.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL or a pointer AD[``i``] to any individual string is NULL while the length ADlen[``i``] is non-zero.
   * - ippStsLengthErr
     - Indicates an error condition that occurs because of one of the following:

       * The keyLen parameter is different from 16, 24, and 32
       * The number of the strings numAD in the AD array is negative or greater than 127
       * The length ADlen[i] of any individual input string is negative
       * The len parameter is negative



