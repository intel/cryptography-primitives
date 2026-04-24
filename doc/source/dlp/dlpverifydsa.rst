.. _dlpverifydsa:

DLPVerifyDSA
============


Verifies the input DSA digital signature.


Syntax
------


IppStatus ippsDLPVerifyDSA(const IppsBigNumState\* pMsg, const
IppsBigNumState\* pSignR, const IppsBigNumState\* pSignS, IppDLResult\*
pResult, IppsDLPState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pMsg
     - Pointer to the message representation *msgRep*.
   * - pSignR
     - Pointer to the signature *r*-component to be verified.
   * - pSignS
     - Pointer to the signature *s*-component to be verified.
   * - pResult
     - Pointer to the result of the verification.
   * - pCtx
     - Pointer to the cryptosystem context.




Description
-----------


The function verifies the input DSA digital signature's components
\*pSignR and \*pSignS with the supplied message representation *msgRep*.
Signer's public key must be stored by the DLPSetKeyPair function before
the DLPVerifyDSA operation.


The function sets the \*pResult to ippDLValid if it validates the input
DSA digital signature, or to ippDLInvalidSignature if the DSA digital
signature verification fails.


:ref:`Example “Use of DLPSignDSA and
DLPVerifyDSA” <example-discrete-logarithm-functions>`
illustrates the use of functions
:ref:`DLPSignDSA <dlpsigndsa>`
and DLPVerifyDSA. The example uses the BigNumber class and functions
creating some cryptographic contexts, whose source code can be found in
:ref:`Appendix A <appendix-a-support-functions-and-classes>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers is NULL.
   * - ippStsContextMatchErr
     - Indicates an error condition if the context parameter does not match the operation.
   * - ippStsIncompleteContextErr
     - Indicates an error condition if the cryptosystem context has not been properly set up.
   * - ippStsMessageErr
     - Indicates an error condition if the value of *msgRep* is negative or greater than the multiplicative subgroup characteristic (*q*).
       Note that since Intel® Integrated Performance Primitives Cryptography (Intel® IPP Cryptography) 2021.4, the *msgRep* parameter can be any non-negative value.



