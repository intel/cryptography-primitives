.. _gfpecprivatekey-gfpecpublickey-gfpectstkeypair:




GFpECPrivateKey, GFpECPublicKey, GFpECTstKeyPair
================================================


Generates a private key of the elliptic curve cryptosystem over GF(p).


Syntax
------


IppStatus ippsGFpECPrivateKey(IppsBigNumState\* pPrivate,
IppsGFpECState\* pEC, IppBitSupplier rndFunc, void\* pRndParam);


IppStatus ippsGFpECPublicKey(const IppsBigNumState\* pPrivate,
IppsGFpECPoint\* pPublic, IppsGFpECState\* pEC, Ipp8u\* pScratchBuffer);


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
     - Pointer to the private key ``privKey``.
   * - pPublic
     - Pointer to the public key ``pubKey``.
   * - pEC
     - Pointer to the context of the elliptic curve.
   * - rndFunc
     - Specified Random Generator.
   * - pRndParam
     - Pointer to the Random Generator context.
   * - pResult
     - Pointer to the validation result.
   * - pScratchBuffer
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


The function generates a private key ``privKey`` of the elliptic
cryptosystem over a finite field GF(``p``). The generation process
employs the user-specified rndFunc Random Generator.


The private key ``privKey`` is a number that lies in the range of [1,
``n``-1] where ``n`` is the order of the elliptic curve base point.


The memory size of the parameter ``privKey`` pointed to by pPrivate must
be not less than order of the base point, which can also be defined by
the function
:ref:`GFpECGetSubgroup <gfpecgetsubgroup>`.


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
     - Indicates an error condition if any of the specified contexts does not match the operation.
   * - ippStsSizeErr
     - Indicates an error condition if the parameter pointed to by pPrivate has a memory size that is less than the order ``n`` of the elliptic curve base point ``G``.
   * - ippStsIvalidPrivateKey
     - Indicates an error condition if the value of the private key is less than that of the order of the elliptic curve base point.



