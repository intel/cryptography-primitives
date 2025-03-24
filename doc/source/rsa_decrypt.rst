.. _rsa_decrypt:



RSA_Decrypt
===========


Performs the RSA decryption operation.


Syntax
------


IppStatus ippsRSA_Decrypt(const IppsBigNumState\* pCtxt,
IppsBigNumState\* pPtxt, const IppsRSAPrivateKeyState\* pKey, Ipp8u\*
pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pCtxt
     -  Pointer to the IppsBigNumState context of the ciphertext.
   * -     pPtxt
     -  Pointer to the IppsBigNumState context of the plaintext.
   * -     pKey
     -  Pointer to the IppsRSAPrivateKeyState context.
   * -     pScratchBuffer
     -  Pointer to the scratch buffer of size not less than returned by the
        :ref:`RSA_GetBufferSizePrivateKey <rsa_getbuffersizepublickey-privatekey>` function.




Description
-----------


The function performs the RSA encryption operation, that is, the RSA
operation on a private key.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr
     -  Indicates an error condition if the context parameter does not match the operation.
   * -     ippStsIncompleteContextErr
     -      Indicates an error condition if the private key is not set up.
   * -     ippStsOutOfRangeErr
     -  Indicates an error condition if the big number specified by pCtxt is not positive or greater than the RSA modulus.
   * -     ippStsSizeErr
     -  Indicates an error condition if the big number specified by pPtxt is not sufficient to hold the result.


.. note:: While you can set up the type 1 private key in a call to RSA_SetPrivateKeyType1, you can set up the type 2 private key in a call to either
          RSA_SetPrivateKeyType2 or RSA_GenerateKeys.


.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsa_generatekeys`
* :ref:`functions-for-building-rsa-system`
