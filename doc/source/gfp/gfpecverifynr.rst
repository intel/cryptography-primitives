.. _gfpecverifynr:



GFpECVerifyNR
=============


Verifies authenticity of the digital signature over a message digest
(the Nyberg-Rueppel scheme).


Syntax
------


IppStatus ippsGFpECVerifyNR(onst IppsBigNumState\* pMsgDigest, const
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
     -  Pointer to the message digest ``msg``.
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


The function verifies authenticity of the digital signature over a
message digest ``msg``. The signature consists of two large integers:
``r`` and ``s``.


The scheme used to compute the digital signature is an elliptic curve
analogue of the El-Gamal Digital Signature scheme with the message
recovery (the Nyberg-Rueppel signature scheme).


You can get the message sender's regular public key ``regPubKey`` by
calling the function
:ref:`GFpECPublicKey <gfpecpublickey>`.


The result of the digital signature verification can take one of two
possible values:


.. list-table::
   :header-rows: 0

   * -     ippECValid
     -  Digital signature is valid.
   * -     ippECInvalidSignature
     -  Digital signature is not valid.




The call to the GFpECVerifyNR function must be preceded by a call to the
:ref:`GFpECSignNR <gfpecsignnr>`
function which computes the digital signature over the message digest
``msg`` and represents the signature with two numbers: ``r`` and ``s``.


The elliptic curve domain parameters must be hitherto defined by the
functions:
:ref:`GFpECInitStd <gfpecinitstd>`,
:ref:`GFpECInit <gfpecinit>`,
:ref:`GFpECSet <gfpecset>`, or
:ref:`GFpECSetSubgroup <gfpecsetsubgroup>`.


For more information on digital signatures, please refer to the
:term:`ANSI <[ANSI]>`
standard.

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
     -  Indicates an error condition if the value of ``msg`` pointed to by pMsgDigest falls outside the range of [1, ``n``-1] where ``n`` is the order of the elliptic curve base point ``G``.
   * -     ippStsRangeErr
     -  Indicates an error condition if any of the parameters pointed to by pSignR or pSignS is negative.
   * -     ippStsOutOfRangeErr
     -  Indicates an error condition if the public key point does not belong to the finite field over which the elliptic curve is initialized.
   * -     ippStsNotSupportedModeErr
     -  Indicates an error condition if the finite field GFp under the elliptic curve is not prime.
   * -     ippStsInvalidPoint
     -  Indicates an error condition if the public key point pRegPublic does not belong to the elliptic curve.



