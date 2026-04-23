.. _hkdf:


HKDF
===========


Computes the output key material from input key material, salt, info,
and hash method per the HKDF standard.


Syntax
------


IppStatus ippsHKDF(const Ipp8u\* ikm, int ikmLen, Ipp8u\* okm,
int okmLen, const Ipp8u\* salt, int saltLen, const Ipp8u\* info, int
infoLen, const IppsHashMethod\* pMethod);


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
   * - okm
     - Pointer to the output keying material.
   * - okmLen
     - Length of needed output keying material in bytes.
   * - salt
     - Pointer to salt value.
   * - saltLen
     - Length of salt value in bytes.
   * - info
     - Pointer to the info.
   * - infoLen
     - Length of the info in bytes.
   * - pMethod
     - Pointer to the hash method context.




Description
-----------


The function computes the output keying material as a part of the Hashed
Message Authentication Code (HMAC)-based key derivation function
(HKDF) as specified in :term:`RFC 5869 <[RFC 5869]>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsLengthErr
     - Indicates an error condition if any of the specified length parameters are invalid.
   * - ippStsNotSupportedModeErr
     - Indicates hash method is not supported
