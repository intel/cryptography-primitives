.. _hkdf_extract:


HKDF_extract
============


Computes the PRK, a pseudorandom key of HashLen bytes, from input keying material, salt,
and hash method per the HKDF standard.


Syntax
------


IppStatus ippsHKDF_extract(const Ipp8u\* ikm, int ikmLen, Ipp8u\* prk, const
Ipp8u\* salt, int saltLen, const IppsHashMethod\* pMethod);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - ikm
     - Pointer to the input keying material.
   * - ikmLen
     - Length of the input keying material in bytes.
   * - prk
     - Pointer to the output pseudorandom key of size HashLen bytes.
   * - salt
     - Pointer to salt value.
   * - saltLen
     - Length of salt value in bytes.
   * - pMethod
     - Pointer to the hash method context.




Description
-----------


The function computes the output PRK pseudorandom key as a part of the
Hashed Message Authentication Code (HMAC)-based key derivation
function (HKDF) as specified in :term:`RFC 5869 <[RFC 5869]>`. The
combination of functions ippsHKDF_extract() & ippsHKDF_expand()
perform the equivalent combined function ippsHKDF().


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr
     - Indicates an error condition if hashLen < 0 or hashLen > MAX_HKDF_HASH_SIZE where MAX_HKDF_HASH_SIZE is the max hash size possible in the library.
   * - ippsStsNotSupportedModeErr
     - Indicates hash method is not supported
