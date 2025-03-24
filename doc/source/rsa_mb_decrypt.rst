.. _rsa_mb_decrypt:


RSA_MB_Decrypt
==============


Performs the RSA multi-buffer decryption operation.


Syntax
------


.. note::


   This API is deprecated from Intel® Cryptography Primitives Library and is removed
   since 2021.2 release. It is recommended to switch to :ref:`Crypto MB <multi-buffer-cryptography-functions>`
   library. If you have any concerns, open a ticket and provide feedback
   at `Intel ® online support
   center <https://supporttickets.intel.com/>`__.


IppStatus ippsRSA_MB_Decrypt(const IppsBigNumState\*pCtxts[8],
IppsBigNumState\*pPtxts[8], const IppsRSAPrivateKeyState\*pKeys[8],
IppStatusstatuses[8], Ipp8u\*pBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pPtxts[8]
     -  Pointer to the IppsBigNumState context of the plaintext for each decryption operation.
   * -     pCtxts[8]
     -  Pointer to the IppsBigNumState context of the ciphertext for each decryption operation.
   * -     pKeys[8]
     -  Pointer to the IppsRSAPublicKeyState context for each decryption operation.
   * -     statuses
     -  Pointer to the IppStatus array that contains statuses for each decryption operation.
   * -     pScratchBuffer
     -  Pointer to the temporary buffer of size not less than returned by the :ref:`RSA_MB_GetBufferSizePrivateKey <rsa_mb_getbuffersizepublickey-privatekey>` function.




Description
-----------


The function performs the RSA multi-buffer decryption operation, which
is the RSA operation on a private key. The function can perform up to 8
single RSA decryption operations at once.


Each RSA decryption operation requires valid parameters that follow the
:ref:`ippsRSA_Decrypt <rsa_decrypt>`
syntax. After execution, the statuses array contains statuses for each
single RSA decryption operation returned by
:ref:`ippsRSA_Decrypt <rsa_decrypt>`.


To perform less than 8 operations, set one or more contexts in arrays to
NULL. In this case, all single operations with NULL in parameters are
not performed, and the function returns ippStsMbWarning .


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   Sizes of all moduli ``n`` in all the IppsRSAPrivateKeyState contexts
   in the pKeys array must be equal. Types of RSA private keys must be
   the same.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -     Indicates no error. All single operations are executed without errors.
     -     Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -     Indicates an error condition if any of the specified pointers is
     -     NULL.
   * -     ippStsSizeErr
     -     Indicates an error condition if the size of modulus ``n`` in one
     -     context is not equal to the size of the modulus ``n`` in other contexts.
   * -     ippStsBadArgErr
     -     Indicates an error condition if types of RSA private keys are not
     -     the same.
   * -     ippStsMbWarning
     -     Indicates a warning when one or more performed operations are
     -     executed with errors. For details, check the statuses array.


.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsa_mb_encrypt`
* :ref:`rsa_generatekeys`
* :ref:`functions-for-building-rsa-system`
