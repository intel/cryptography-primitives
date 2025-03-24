.. _dlpvalidatekeypair:



DLPValidateKeyPair
==================


Validates private and public keys of the DL-based cryptosystem over
GF(p).


Syntax
------


IppStatus ippsDLPValidateKeyPair(const IppsBigNumState\* pPrivate, const
IppsBigNumState\* pPublic, IppDLResult\* pResult, IppsDLPState\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pPrivate   
     - Pointer to the input private key *privKey*.
   * - pPublic   
     - Pointer to the output public key *pubKey*.
   * - pResult   
     - Pointer to the validation result.
   * - pCtx   
     - Pointer to the cryptosystem context.




Description
-----------


The function validates the private key *privKey* and the public key
*pubKey* of the DL-based cryptosystem. The result of the validation is
stored in the \*pResult and may be assigned to one of the enumerators
listed below:


.. list-table:: 
   :header-rows: 0

   * - ippDLValid   
     - Validation has passed successfully.
   * - ippDLInvalidPrivateKey   
     - (1 < ``private`` < (``R``- 1)) is false.
   * - ippDLInvalidPublicKey   
     - (1 < ``public``\ ≤ (``P``- 1)) is false.
   * - ippDLInvalidKeyPair   
     - ``public`` != ``G``\ ^\ ``private`` (mod ``P``).




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



