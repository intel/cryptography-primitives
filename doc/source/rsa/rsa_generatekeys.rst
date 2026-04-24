.. _rsa_generatekeys:



RSA_GenerateKeys
================


Generates key components for the desired RSA cryptographic system.


Syntax
------


IppStatus ippsRSA_GenerateKeys(const IppsBigNumState\* pSrcPublicExp,
IppsBigNumState\* pModulus, IppsBigNumState\* pPublicExp,
IppsBigNumState\* pPrivateExp, IppsRSAPrivateKeyState\*
pPrivateKeyType2, Ipp8u\* pScratchBuffer, int nTrials, IppsPrimeState\*
pPrimeGen, IppBitSupplier rndFunc, void\* pRndParam);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pSrcPublicExp
     -  Pointer to the IppsBigNumState context of the initial value for searching an RSA public exponent.
   * -     pModulus
     -  Pointer to the generated RSA modulus.
   * -     pPublicExp
     -  Pointer to the generated RSA public exponent.
   * -     pPrivateExp
     -  Pointer to the generated RSA private exponent.
   * -     pPrivateKeyType2
     -  Pointer to the generated RSA private key type 2.
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


This function generates public and private keys of the desired RSA
cryptographic system.


This function sequentially performs the following computations:


#. Generates random probable prime numbers ``p`` and ``q`` using the
   specified pseudorandom number generator rndFunc.


#. Computes the RSA composite modulus ``n = (p*q)``.


#. Based on the generated ``p`` and ``q`` factors, computes all the
   other CRT-related RSA components: ``dP`` = ``d`` mod (``p``-1),
   ``dQ`` = ``p`` mod (``q``-1) and ``qInv`` = 1/``q`` mod ``p``.


To generate RSA keys using the RSA_GenerateKeys function, call it in the
following sequence of steps:


#. Establish the pseudorandom number generator and prime number
   generator.


#. Define the RSA private key type 2 in successive calls to the
   RSA_GetSizePrivateKeyType2 and RSA_InitPrivateKeyType2 functions with
   desired values of factorPBitSize and factorQBitSize parameters.


#. Allocate a temporary buffer of a suitable size.


#. Set up the initial value of the public exponent pSrcPublicExp.


#. Call RSA_GenerateKeys.

   * If RSA_GenerateKeys returns IppNoErr, the key pair is generated.
   * If RSA_GenerateKeys returns ippStsInsufficientEntropy, repeat this step.


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
     -      Indicates an error condition if the bit length of any key component specified by pModulus, pPublicExp or pPrivateExp is not sufficient to hold the value or the prime number generator, specified by pPrimeGen, is not sufficient to generate suitable values.
   * -      ippStsOutOfRangeErr
     -      Indicates an error condition if the initial value for searching the public exponent, specified by pSrcPublicExp, is not positive.
   * -     ippStsBadArgErr
     -      Indicates an error condition in cases not explicitly mentioned above.
   * -     ippStsInsufficientEntropy
     -      Indicates a warning condition if the prime number generation fails due to a poor choice of entropy.


.. rubric:: Related Information

* :ref:`rsa_initpublickey-privatekeytype1-type2`
* :ref:`rsa_validatekeys`
* :ref:`pseudorandom-number-generation-functions`


