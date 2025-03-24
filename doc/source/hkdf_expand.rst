.. _hkdf_expand:


HKDF_expand
===========


Computes the output key material from input key material, salt, info,
and hash method per the HKDF standard.


Syntax
------


IppStatus ippsHKDF_expand(const Ipp8u\* ikm, int ikmLen, Ipp8u\* okm,
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
     - Pointer to the input key message.
   * - ikmLen
     - Length of the input key message in bytes.
   * - okm
     - Pointer to the output key message.
   * - okmLen
     - Length of needed output key message in bytes.
   * - salt
     - Pointer to salt message.
   * - saltLen
     - Length of salt message in bytes.
   * - info
     - Pointer to the info message.
   * - infoLen
     - Length of the info message in bytes.
   * - pMethod
     - Pointer to the hash method context.




Description
-----------


The function computes the output message as a part of the Hashed
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
   * - ippsStsNotSupportedModeErr
     - Indicates hash method is not supported
