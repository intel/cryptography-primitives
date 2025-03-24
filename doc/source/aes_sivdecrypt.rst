.. _aes_sivdecrypt:

AES_SIVDecrypt
==============


Performs the SIV authenticated decryption using the AES cipher.


Syntax
------


IppStatus ippsAES_SIVDecrypt(const Ipp8u\* pSrc, Ipp8u\* pDst, int len,
int\* pAuthPassed, const Ipp8u\* pAuthKey, const Ipp8u\* pConfKey, int
keyLen, const Ipp8u\* AD[], const int ADlen[], int numAD, const Ipp8u\*
pSIV);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pSrc
     - Pointer to the input data to decrypt (ciphertext).
   * - pDst
     - Pointer to the output decrypted data (plaintext).
   * - len
     - Length in bytes of the plaintext and ciphertext.
   * - pAuthPassed
     - Pointer to the result flag.
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
   * - pSIV
     - Pointer to the synthetic initialization vector.




Description
-----------


The AES_SIVDecrypt function acceptsauthentication and confidentiality
keys of length keyLen each, a vector AD[] of associated data(strings),
16-byte synthetic initialization vector (\*pSIV), and ciphertext
(\*pSrc) of an arbitrarylength len. The output of the function is the
decrypted plaintext (\*pDst) of the same length as theciphertext and the
result of plaintext authentication (\*pAuthPassed).


The computation includes the following steps:


#. Decrypt the input ciphertext using the AES cipher in the CTR mode
   with the initial counter value (``CTR0``) equal to the synthetic
   initialization vector (\*pSIV) xored with a fixed mask.


#. Re-compute the synthetic initialization vector using the input data
   AD[] and the computed plaintext.


If the input and re-computed values ofSIV are the same, the plaintext
authentication is considered passed (\*pAuthPassed = 1), otherwise, the
plaintextauthentication is considered failed (\*pAuthPassed = 0).


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL
       or a pointer AD[``i``] to any individual string is NULL while the length ADlen[``i``] is non-zero.
   * - ippStsLengthErr
     - Indicates an error condition that occurs because of one of the following:

       * The keyLen parameter is different from 16, 24, and 32
       * The number of the strings numAD in the AD array is negative or greater than 127
       * The length ADlen[i] of any individual input string is negative
       * The len parameter is negative



