.. _gfpecpsharedsecretdh-gfpecpsharedsecretdhc:


GFpECPSharedSecretDH, GFpECPSharedSecretDHC
===========================================


Computes a shared secret field element by using the Diffie-Hellman
scheme.


Syntax
------


IppStatus ippsGFpECSharedSecretDH(const IppsBigNumState\* pPrivateA,
const IppsGFpECPoint\* pPublicB, IppsBigNumState\* pShare,
IppsGFpECState\* pEC, Ipp8u\* pScratchBuffer);


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

   * - pPrivateA   
     - Pointer to your own private key ``privKey``.
   * - pPublicB   
     - Pointer to the public key ``pubKey``.
   * - pShare   
     - Pointer to the secret number ``bnShare``.
   * - pEC   
     - Pointer to the context of the elliptic curve.
   * - pScratchBuffer   
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


The function computes a secret number bnShare, which is a secret key
shared between two participants of the cryptosystem.


The ippsGFpECSharedSecretDH function computes elliptic point
``P =``\ ``[pPrivateA]``\ · ``pPublicB``. In the
ippsGFpECSharedSecretDHC function the ``h`` cofactor is used:
``P =``\ ``[h]``\ ``[pPrivateA]``\ · ``pPublicB``.

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
     - Indicates an error condition if one of the contexts pointed to by pPublicB, pPrivateA, pShare, or pEC is not valid.
   * - ippStsRangeErr   
     - Indicates an error condition if the memory size of ``bnShare`` pointed to by pShare is less than the size of the GFp modulus that is base for the specified elliptic curve.
   * - ippStsShareKeyErr   
     - Indicates an error condition if the shared secret key is not valid. (For example, the shared secret key is invalid if the result of the secret point calculation is the point at infinity.)



