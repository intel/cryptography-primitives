.. _gfpecverifysm2:


GFpECVerifySM2
==============


Verifies authenticity of a digital signature over a message digest using
the SM2 scheme.


Syntax
------


IppStatus ippsGFpECVerifySM2(const IppsBigNumState\* pMsgDigest, const
IppsGFpECPoint\* pRegPublic, const IppsBigNumState\* pSignR, const
IppsBigNumState\* pSignS, IppECResult\* pResult, IppsGFpECState\* pEC,
Ipp8u\* pScratchBuffer);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pMsgDigest
     -  Pointer to the message digest *msg*.
   * -     pRegPublic
     -  Pointer to the signer's regular public key.
   * -     pSignR
     -  Pointer to the integer ``r`` of the digital signature.
   * -     pSignS
     -  Pointer to the integer ``s`` of the digital signature.
   * -     pResult
     -  Pointer to the digital signature verification result.
   * -     pEC
     -  Pointer to the context of the elliptic curve.
   * -     pScratchBuffer
     -  Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


The function verifies authenticity of the digital signature, represented
as integer big numbers ``r`` and ``s``, over a message digest *msg*. The
digital signature over the message digest *msg* must be computed using
the SM2 scheme
:term:`SM2 <[SM2]>` by to the
:ref:`GFpECSignSM2 <gfpecsignsm2>`
function.


You can get the message sender's regular public key ``regPubKey`` by
calling the function
:ref:`GFpECPublicKey <gfpecpublickey>`.


The result of the digital signature verification can take one of these
values:


.. list-table::
   :header-rows: 0

   * -     ippECValid
     -  Digital signature is valid.
   * -     ippECInvalidSignature
     -  Digital signature is not valid.




The elliptic curve domain parameters must be hitherto defined by the
functions:
:ref:`GFpECInitStd <gfpecinitstd>`,
:ref:`GFpECInit <gfpecinit>`,
:ref:`GFpECSet <gfpecset>`, or
:ref:`GFpECSetSubgroup <gfpecsetsubgroup>`.

.. note::

   The SM2-specific optimized code paths of this function are selected only
   for an elliptic curve context initialized with the
   :ref:`GFpECInitStd <gfpecinitstd>` function for the SM2 curve. An SM2 curve
   defined manually with :ref:`GFpECInit <gfpecinit>` and
   :ref:`GFpECSet <gfpecset>`/:ref:`GFpECSetSubgroup <gfpecsetsubgroup>`
   produces correct results but uses the generic code path.

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 2 to get the valid *pScratchBuffer*.

Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr
     -  Indicates an error condition if any of the contexts pointed to by pMsgDigest, pRegPublic, pSignR, pSignS, or pEC does not match the operation.
   * -     ippStsMessageErr
     -  Indicates an error condition if the value of ``msg`` pointed to by pMsgDigest falls outside the range of [1, ``n``-1], where ``n`` is the order of the elliptic curve base point ``G``.
   * -     ippStsRangeErr
     -  Indicates an error condition if any of the parameters pointed to by pSignR or pSignS is negative.
   * -     ippStsOutOfRangeErr
     -  Indicates an error condition if the public key point does not belong to the finite field over which the elliptic curve is initialized.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if the finite field GFp under the elliptic curve is not prime.



