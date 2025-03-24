.. _rsa_mb_verify_pss_rmf:



RSA_MB_Verify_PSS_rmf
=====================


Performs RSA multi-buffer signature verification using RSASSA-PSS
scheme.


Syntax
------


.. note::


   This API is deprecated from Intel® Cryptography Primitives Library and is removed
   since 2021.2 release. It is recommended to switch to :ref:`Crypto MB <multi-buffer-cryptography-functions>`
   library. If you have any concerns, open a ticket and provide feedback
   at `Intel ® online support
   center <https://supporttickets.intel.com/>`__.


IppStatus ippsRSA_MB_Verify_PSS_rmf(const Ipp8u\*pMsgs[8],const
intmsgLens[8],const Ipp8u\*pSignts[8],intpIsValid[8], const
IppsRSAPublicKeyState\*pPubKeys[8], const IppsHashMethod\*pMethod,
IppStatusstatuses[8], Ipp8u\*pBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pMsgs[8]
     -  Pointer to the array of messages that have been signed.
   * -     msgLens[8]
     -  Pointer to the array of messages lengths.
   * -     pSignts[8]
     -  Pointer to the array of signatures to be verified.
   * -     pIsValid
     -  Pointer to the array of verification results.
   * -     pPubKeys[8]
     -  Pointer to the array of preliminary initialized IppsRSAPublicKeyState contexts.
   * -     pMethod
     -  Pointer to the hash method. For details, see :ref:`HashMethod <hashmethod>` functions.
   * -     statuses[8]
     -  Pointer to the array of execution statuses for each performed operation.
   * -     pBuffer
     -  Pointer to a temporary buffer. The size of the buffer must be not less than the value returned by the :ref:`RSA_MB_GetBufferSizePublicKey <rsa_mb_getbuffersizepublickey-privatekey>` function.




Description
-----------


This function carries out the RSASSA-PSS signature verification scheme
defined in :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`. The
function can perform up to 8 verification operations at once.


Specify parameters for each single signature verification operation
under the corresponding index in an input array in accordance with the
:ref:`ippsRSAVerify_PSS_rmf <rsaverify_pss>`
function API requirements.


To perform less than 8 operations, set one or more pointers to a context
in input context arrays to NULL. In this case, each single operation
with the context set to NULL will not be performed, and the function
will return ippStsMbWarning . Once the function execution is completed,
the statuses array will contain return codes for each single signature
verification operation according to the
:ref:`ippsRSAVerify_PSS_rmf <rsaverify_pss>`
return values.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   -  Sizes of all moduli ``n`` in all IppsRSAPublicKeyState contexts in
      the pPubKeys array must be equal.


   -  Sizes and values of all public exponents ``e`` in all
      IppsRSAPublicKeyState contexts in the pPubKeys array must be
      equal.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -     Indicates no error. All single operations executed without errors. Any other value indicates an error or warning.
   * -     ippStsMbWarning
     -     One or more of performed operations executed with error. Check statuses array for details.
   * -     ippStsNullPtrErr
     -     Any of the input parameters is a NULL pointer.
   * -     ippStsSizeErr
     -     Indicates a mismatch between moduli ``n`` sizes in the input contexts.
   * -     ippStsBadArgErr
     -     Indicates a mismatch between exponents ``e`` in public keys.
   * -     ippStsContextMatchErr
     -     No valid keys were found.



.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsa_mb_sign_pss_rmf`
