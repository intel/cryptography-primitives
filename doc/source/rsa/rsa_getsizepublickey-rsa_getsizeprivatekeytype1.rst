.. _rsa_getsizepublickey-privatekeytype1-type2:


RSA_GetSizePublicKey, RSA_GetSizePrivateKeyType1, RSA_GetSizePrivateKeyType2
============================================================================


Get the size of the IppsRSAPublicKeyState or IppsRSAPrivateKeyState
context.


Syntax
------


IppStatus ippsRSA_GetSizePublicKey(int rsaModulusBitSize, int
publicExpBitSize, int\* pKeySize);


IppStatus ippsRSA_GetSizePrivateKeyType1(int rsaModulusBitSize, int
privateExpBitSize, int\* pKeySize);


IppStatus ippsRSA_GetSizePrivateKeyType2(int factorPBitSize, int
factorQBitSize, int\* pKeySize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     rsaModulusBitSize
     -  Length of the RSA system in bits (that is, the length of the composite RSA modulus n in bits).
   * -     publicExpBitSize
     -  Length of the RSA public exponent in bits (that is, the length of the ``e`` component of the RSA public key).
   * -     privateExpBitSize
     -  Length of the RSA private exponent in bits (that is, the length of the ``d`` component of the RSA private key type 1).
   * -     factorPBitSize, factorQBitSize
     -  Length in bits of the ``p`` and ``q`` factors of the RSA modulus ``n`` = ``p``\ \*\ ``q``.
   * -     pKeySize
     -  Pointer to the IppsRSAPublicKeyState context size in bytes.




Description
-----------


These functions get the size of the IppsRSAPublicKeyState or
IppsRSAPrivateKeyState context in bytes and stores it in \*pKeySize.
Call RSA_GetSizePublicKey to establish an RSA cryptosystem for
encryption (or signature verification) operations. Call
RSA_GetSizePrivateKeyType1 or RSA_GetSizePrivateKeyType2 to establish an
RSA cryptosystem for decryption (or signature generation) operations.
The choice between these two functions depends on the representation of
the private key to be used.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if rsaModulusBitSize < 32, rsaModulusBitSize > 4096, factorPBitSize + factorQBitSize < 32, factorPBitSize + factorQBitSize > 4096, factorPBitSize < 0, or factorQBitSize < 0.
   * -     ippStsBadArgErr
     - * For RSA_GetSizePublicKey, indicates an error condition if publicExpBitSize < 0 or publicExpBitSize > rsaModulusBitSize.
       * For RSA_GetSizePrivateKeyType1, indicates and error condition if privateExpBitSize <0 or privateExpBitSize > rsaModulusBitSize.
       * For RSA_GetSizePrivateKeyType2, indicates and error condition if factorPBitSize <0, factorPBitSize < 0, or factorPBitSize < factorQBitSize.



