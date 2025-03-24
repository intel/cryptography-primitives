.. _gfpecsharedsecretdhc:



GFpECSharedSecretDHC
====================


Computes a shared secret field element by using the Diffie-Hellman
scheme and the elliptic curve cofactor.


Syntax
------


IppStatus ippsGFpECSharedSecretDHC(const IppsBigNumState\* pPrivateA,
const IppsGFpECPoint\* pPublicB, IppsBigNumState\* pShare,
IppsGFpECState\* pEC, Ipp8u\* pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pPrivate   
     - Pointer to your own private key ``privKey``.
   * - pPublic   
     - Pointer to the public key ``pubKey``.
   * - pShare   
     - Pointer to the secret number ``bnShare``.
   * - pEC   
     - Pointer to the context of the elliptic curve.
   * - pScratchBuffer   
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


The function computes a secret number bnShare which is a secret key
shared between two participants of the cryptosystem. Both participants
(Alice and Bob) use the cryptosystem for getting a common secret point
on the elliptic curve by using the Diffie-Hellman scheme and elliptic
curve cofactor *h*.


Alice and Bob perform the following operations:


#. Alice calculates her own public key ``pubKeyA`` by using her private
   key ``privKeyA``: ``pubKeyA = privKeyA``\ · ``G``, where ``G`` is the
   base point of the elliptic curve. Alice passes the public key to Bob.
#. Bob calculates his own public key ``pubKeyB`` by using his private
   key ``privKeyB``: ``pubKeyB = privKeyB``\ · ``G``, where ``G`` is a
   base point of the elliptic curve. Bob passes the public key to Alice.
#. Alice gets Bob's public key and calculates the secret point
   ``shareA``. When calculating, she uses her own private key and Bob's
   public key and applies the following formula:``shareA =``\ ``h``\ ·
   ``privKeyA``\ · ``pubKeyB =``\ ``h``\ · ``privKeyA``\ ·
   ``privKeyB``\ · ``G``, where ``h``\ is the elliptic curve cofactor.
#. Bob gets Alice's public key and calculates the secret point
   ``shareB``. When calculating, he uses his own private key and Alice's
   public key and applies the following formula:``shareB =``\ ``h``\ ·
   ``privKeyB``\ · ``pubKeyA =``\ ``h``\ · ``privKeyB``\ ·
   ``privKeyA``\ · ``G``, where ``h``\ is the elliptic curve cofactor.


Shared secret bnShare is the x-coordinate of the secret point on the
elliptic curve.


The elliptic curve domain parameters must be hitherto defined by the
functions:
:ref:`GFpECInitStd <gfpecinitstd>`,
:ref:`GFpECInit <gfpecinit>`,
:ref:`GFpECSet <gfpecset>`, or
:ref:`GFpECSetSubgroup <gfpecsetsubgroup>`.

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 1 to get the valid *pScratchBuffer*.

Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the contexts pointed to by pPrivate, pPublic, pShare, or pEC does not match the operation.
   * - ippStsRangeErr   
     - Indicates an error condition if the memory size of ``bnShare`` pointed to by pShare is less than the size of the GFp modulus that is the base for the specified elliptic curve.
   * - ippStsShareKeyErr   
     - Indicates an error condition if the shared secret key is not valid. (For example, the shared secret key is invalid if the result of the secret point calculation is the point at infinity.)



