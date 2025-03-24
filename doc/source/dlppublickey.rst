.. _dlppublickey:

DLPPublicKey
============


Computes a public key from the given private key of the DL-based
cryptosystem over GF(p).


Syntax
------


IppStatus ippsDLPPublicKey(const IppsBigNumState\* pPrivate,
IppsBigNumState\* pPublic, IppsDLPState\* pCtx);


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
   * - pCtx   
     - Pointer to the cryptosystem context.




Description
-----------


The function computes a public key *pubKey* of the DL-based
cryptosystem.


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
   * - ippStsInvalidPrivateKey   
     - Indicates an error condition if the *privKey* has an illegal value.
   * - ippStsRangeErr   
     - Indicates an error condition if Big Number specified by pPublic is too small for the DL public key.



