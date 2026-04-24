.. _rsa_validatekeys:

RSA_ValidateKeys
================


Validates key components of the RSA cryptographic system.


Syntax
------


IppStatus ippsRSA_ValidateKeys(int\* pResult, const
IppsRSAPublicKeyState\* pPublicKey, const IppsRSAPrivateKeyState\*
pPrivateKeyType2, const IppsRSAPrivateKeyState\* pPrivateKeyType1,
Ipp8u\* pScratchBuffer, int nTrials, IppsPrimeState\* pPrimeGen,
IppBitSupplier rndFunc, void\* pRndParam);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pResult   
     -  Pointer to the result of validation.
   * -     pPublicKey   
     -  Pointer to the RSA public key.
   * -     pPrivateKeyType2   
     -  Pointer to the RSA private key type 2.
   * -     pPrivateKeyType1   
     -  Pointer to the RSA private key type 1. This parameter is optional and can have the value of NULL.
   * -     pScratchBuffer   
     -  Pointer to the temporary buffer of size not less than returned by the :ref:`RSA_GetBufferSizePrivateKey <rsa_getbuffersizepublickey-privatekey>` function.
   * -     nTrials   
     -  Security parameter specified for the Miller-Rabin test for probable primality.
   * -     pPrimeGen   
     -  Pointer to the prime number generator.
   * -     rndFunc   
     -  Pseudorandom number generator.
   * -     pRndParam   
     -  Pointer to the context of the pseudorandom number generator.




Description
-----------


The function validates key components of the RSA cryptographic system
and stores the result of the validation procedure in \*pResult.


The meanings of values of \*pResult are as follows:


.. list-table:: 
   :header-rows: 0

   * -     IS_VALID_KEY   
     -     The RSA key pair is valid.   
   * -     IS_INVALID_KEY   
     -     The RSA key is not valid.   




The key pair is valid under the following conditions:


-  The ``p`` and ``q`` factors are prime.


-  The type 2 private key meets these conditions:


   -  ``e*dP`` = 1 (mod ``p``-1) and ``e*dQ`` = 1 (mod ``q`` -1)


   -  ``q*qInv`` = 1 (mod ``p``)


-  If the pPrivateKeyType1 parameter is not NULL, the type 1 private key
   meets the condition ``e``\ \*\ ``d`` = 1 mod ((``p``-1)*(``q``-1)).


Validation of the public and type 1 private key pair requires type 2
private key.


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
   * -     ippStsSizeErr   
     -      Indicates an error condition if the prime number generator, specified by pPrimeGen, is not sufficient to generate suitable values.   
   * -     ippStsIncompleteContextErr   
     -      Indicates an error condition if the public or private key is not set up.   
   * -     ippStsBadArgErr   
     -     Indicates an error condition if any of the RSA keys \*pPublicKey, \*pPrivateKeyType2, or, optional, \*pPrivateKeyType1 is not properly set up or generated.   


.. rubric:: Related Information

:ref:`rsa_generatekeys`


