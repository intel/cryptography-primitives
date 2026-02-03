.. _pkcs5_pbkdf2:

pkcs5_pbkdf2
============

Computes the PKCS #5 Key Derivation Function PBKDF2 from input
password string, salt and hash method per the PKCS #5 standard.

Additional library restriction is that salt length must be less than
MAX_PKCS5_HASH_SIZE (set at maximum hash size in library).

Syntax
------

IppStatus ippsPBKDF2_PKCS5v2(const Ipp8u\* pass, int passLen,
Ipp8u\* odk,  int odkLen,
const Ipp8u\* salt, int saltLen,
int c,
const IppsHashMethod\* pMethod);


Include Files
-------------


``ippcp.h``


Parameters
----------

.. list-table::
   :header-rows: 0

   * - pass
     - Pointer to the input password.
   * - passLen
     - Length of the input password in bytes. Spec max of (2^32 - 1) * hash_len is never possible with int.
   * - odk
     - Pointer to the output derived key.
   * - odkLen
     - Length of needed output derived key in bytes.
   * - salt
     - Pointer to salt message.
   * - saltLen
     - Length of salt message in bytes. Must be >= 8 bytes and <= MAX_PKCS5_HASH_SIZE (set at maximum hash size in library).
   * - c
     - Number of internal iterations required. Must be >= 1000.
   * - pMethod
     - Pointer to the hash method context.




Description
-----------

The function computes a derived key as specified in PKCS #5 Key
Derivation Function PBKDF2, :term:`RFC 8018 <[RFC 8018]>` Section-5.2.



Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the input pointers is NULL.
   * - ippStsLengthErr
     - Indicates an error condition if any of the specified length parameters are invalid including saltLen > MAX_PKCS5_HASH_SIZE (set at maximum hash size in library).
   * - ippStsNotSupportedModeErr
     - Indicates hash method is not supported

