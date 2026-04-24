.. _gfpectstkeypair:


GFpECTstKeyPair
===============


Tests private and public keys of the elliptic curve cryptosystem over
GF(p).


Syntax
------


IppStatus ippsGFpECTstKeyPair(const IppsBigNumState\* pPrivate, const
IppsGFpECPoint\* pPublic, IppECResult\* pResult, IppsGFpECState\* pEC,
Ipp8u\* pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pPrivate   
     - Pointer to the private key privKey.
   * - pPublic   
     - Pointer to the public key pubKey.
   * - pResult   
     - Pointer to the validation result.
   * - pEC   
     - Pointer to the context of the elliptic curve.
   * - pScratchBuffer   
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


The function tests the private key *privKey* and public key *pubKey* of
the elliptic curve cryptosystem over a finite field GF(``p``) and
allocates the result of the validation in accordance with the pointer
pResult.


The private key *privKey* is a number that lies in the range of [1,
*n*-1] where *n* is the order of the elliptic curve base point. The
public key *pubKey* is an elliptic curve point such that
``pubKey = privKey``\ · ``G``, where ``G`` is the base point of the
elliptic curve.


The elliptic curve domain parameters must be hitherto defined by the
functions:
:ref:`GFpECInitStd <gfpecinitstd>`,
:ref:`GFpECInit <gfpecinit>`,
:ref:`GFpECSet <gfpecset>`, or
:ref:`GFpECSetSubgroup <gfpecsetsubgroup>`.


The result of the cryptosystem keys validation for correctness can take
one of the following values:

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 1 to get the valid *pScratchBuffer*.


.. list-table:: 
   :header-rows: 0

   * - ippECValid   
     - Keys are valid.
   * - ippECInvalidKeyPair   
     - Keys are not valid because ``privKey``\ · ``G`` ≠ ``pubKey``
   * - ippECInvalidPrivateKey   
     - Key *privKey* falls outside the range of [1, *n*-1].
   * - ippECPointIsAtInfinite   
     - Key *pubKey* is the point at infinity.
   * - ippECInvalidPublicKey   
     - Key *pubKey* is not valid because *n* · ``pubKey`` ≠ *O* , where *O* is the point at infinity.




Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the contexts pointed by pPrivate, pPublic, or pEC does not match the operation.
   * - ippStsRangeErr   
     - Indicates an error condition if the public key point does not belong to the finite field over which the elliptic curve is initialized.



