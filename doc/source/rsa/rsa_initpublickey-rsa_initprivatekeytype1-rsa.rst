.. _rsa_initpublickey-privatekeytype1-type2:


RSA_InitPublicKey, RSA_InitPrivateKeyType1, RSA_InitPrivateKeyType2
===================================================================


Initialize user-supplied memory as the IppsRSAPublicKeyState or
IppsRSAPrivateKeyState context for future use.


Syntax
------


IppStatus ippsRSA_InitPublicKey(int rsaModulusBitSize, int
publicExpBitSize, IppsRSAPublicKeyState\* pKey, int keyCtxSize);


IppStatus ippsRSA_InitPrivateKeyType1(int rsaModulusBitSize, int
privateExpBitSize, IppsRSAPrivateKeyState\* pKey, int keyCtxSize);


IppStatus ippsRSA_InitPrivateKeyType2(int factorPBitSize, int
FactorQBitSize, IppsRSAPrivateKeyState\* pKey, int keyCtxSize);


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
     -  Length of the RSA private exponent in bits (that is, the length of the ``d`` component of the type 1 RSA private key).
   * -     factorPBitSize, FactorQBitSize
     -  Length in bits of the ``p`` and ``q`` factors of the RSA modulus ``n`` = ``p``\ \*\ ``q``.
   * -     pKey
     -  Pointer to the IppsRSAPublicKeyState or IppsRSAPrivateKeyState context being initialized. The context depends on the function.
   * -     keyCtxSize
     -  Available size in bytes of the memory buffer being initialized.




Description
-----------


These functions initialize the memory pointed by pKey as the
IppsRSAPublicKeyState or IppsRSAPrivateKeyState context, depending on
the function. To determine the size of the memory buffer, call the
appropriate :ref:`RSA_GetSizePublicKey, RSA_GetSizePrivateKeyType1,
RSA_GetSizePrivateKeyType2 <rsa_getsizepublickey-privatekeytype1-type2>`
function prior to calling any of these functions.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if rsaModulusBitSize < 32 or rsaModulusBitSize > 4096, factorPBitSize < 16 or factorPBitSize > 4096, or factorQBitSize < 16 or factorQBitSize > 4096.
   * -     ippStsBadArgErr
     -  Indicates an error condition if publicExpBitSize > rsaModulusBitSize or privateExpBitSize > rsaModulusBitSize.
   * -     ippStsMemAllocErr
     -  Indicates an error condition if the allocated memory is insufficient for the operation.




.. rubric:: Related Information

* :ref:`rsa_getsizepublickey-privatekeytype1-type2`
* :ref:`data-security-considerations`
