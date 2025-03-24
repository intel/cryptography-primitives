.. _gfpecpverifydsa-gfpecpverifynr-gfpecpverifysm2:


GFpECPVerifyDSA, GFpECPVerifyNR, GFpECPVerifySM2
================================================


Verifies authenticity of the digital signature over a message digest
(ECDSA).


Syntax
------


IppStatus ippsGFpECVerifyDSA(const IppsBigNumState\* pMsgDigest, const
IppsGFpECPoint\* pRegPublic, const IppsBigNumState\* pSignR, const
IppsBigNumState\* pSignS, IppECResult\* pResult, IppsGFpECState\* pEC,
Ipp8u\* pScratchBuffer);


IppStatus ippsGFpECVerifyNR(onst IppsBigNumState\* pMsgDigest, const
IppsGFpECPoint\* pRegPublic, const IppsBigNumState\* pSignR, const
IppsBigNumState\* pSignS, IppECResult\* pResult, IppsGFpECState\* pEC,
Ipp8u\* pScratchBuffer);


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

   * - pMsgDigest   
     - Pointer to the message digest ``msg``.
   * - pRegPublic   
     - Pointer to the signer's regular public key.
   * - pSignR   
     - Pointer to the integer ``r`` of the digital signature.
   * - pSignS   
     - Pointer to the integer ``s`` of the digital signature.
   * - pResult   
     - Pointer to the digital signature verification result.
   * - pEC   
     - Pointer to the context of the elliptic curve.
   * - pScratchBuffer   
     - Pointer to the scratch buffer of size produced by *ippsGFpECScratchBufferSize*.




Description
-----------


These functions verify authenticity of the digital signature generated
by the ippsGFpECPSignDSA , ippsGFpECPSignNR, and
ippsGFpECPSignSM2functions, respectively. The signature consists of two
large integers: ``r`` and ``s``.

The *ippsGFpECScratchBufferSize* function should be called with *nScalars* equal to at least 2 to get the valid *pScratchBuffer*.

Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr   
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr   
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr   
     - Indicates an error condition if any of the contexts pointed to by pMsgDigest, pRegPublic, pSignR, pSignS, or pEC does not match the operation.
   * - ippStsMessageErr   
     - Indicates an error condition if the value of ``msg`` pointed to by pMsgDigest falls outside the range of [1, ``n``-1], where ``n`` is the order of the elliptic curve base point ``G``.
   * - ippStsRangeErr   
     - Indicates an error condition if any of the parameters pointed to by pSignR or pSignS is negative.



