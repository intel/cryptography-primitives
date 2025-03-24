.. _rsa_encrypt:


RSA_Encrypt
===========


Performs the RSA encryption operation.


Syntax
------


IppStatus ippsRSA_Encrypt(const IppsBigNumState\* pPtxt,
IppsBigNumState\* pCtxt, const IppsRSAPublicKeyState\* pKey, Ipp8u\*
pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pPtxt   
     -  Pointer to the IppsBigNumState context of the plaintext.
   * -     pCtxt   
     -  Pointer to the IppsBigNumState context of the ciphertext.
   * -     pKey   
     -  Pointer to the IppsRSAPublicKeyState context.
   * -     pScratchBuffer   
     -  Pointer to the temporary buffer of size not less than returned by the :ref:`RSA_GetBufferSizePublicKey <rsa_getbuffersizepublickey-privatekey>` function.




Description
-----------


The function performs the RSA encryption operation, that is, the RSA
operation on a public key.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -      Indicates no error. Any other value indicates an error or warning.   
   * -     ippStsNullPtrErr   
     -      Indicates an error condition if any of the specified pointers is NULL.   
   * -     ippStsContextMatchErr   
     -      Indicates an error condition if the context parameter does not match the operation.   
   * -     ippStsIncompleteContextErr   
     -     Indicates an error condition if the public key is not set up.   
   * -     ippStsOutOfRangeErr   
     -     Indicates an error condition if the big number specified by pPtxt is not positive or greater than the RSA modulus.   
   * -     ippStsSizeErr   
     -     Indicates an error condition if the big number specified by pCtxt is not sufficient to hold the result.   


.. note:: You can set up the public key in a call to ``RSA_SetPublicKey``.


.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsa_decrypt`
* :ref:`functions-for-building-rsa-system`
