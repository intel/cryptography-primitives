.. _aes_s2v_cmac:


AES_S2V_CMAC
============


Produces the synthetic initialization vector.


Syntax
------


IppStatus ippsAES_S2V_CMAC(const Ipp8u\* pKey, int keyLen, const Ipp8u\*
AD[], const int ADlen[], int numAD, Ipp8u\* pSIV);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pKey
     - Pointer to the key.
   * - keyLen
     - Length of the key in bytes.
   * - AD
     - Array of pointers to individual input strings.
   * - ADlen
     - Array of length (in bytes) of the individual input strings.
   * - numAD
     - The number of the strings.
   * - pSIV
     - Pointer to the output 16-byte vector.




Description
-----------


The AES_S2V_CMAC function takes a key and maps the vector of individual
strings AD[0], AD[1], …, AD[numAD-1] to the 16-byte output vector.


The function uses pseudorandom AES_CMACfunctions to process each input
string, as well as doubling and xoringoperations to map the output toa
single output vector.


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
       * The number of the strings numAD in the AD array is negative
       * The length ADlen[i] of any individual input string is negative



