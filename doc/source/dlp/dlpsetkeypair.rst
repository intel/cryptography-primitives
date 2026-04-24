.. _dlpsetkeypair:

DLPSetKeyPair
=============


Sets private and/or public keys of the DL-based cryptosystem over GF(p).


Syntax
------


IppStatus ippsDLPSetKeyPair(const IppsBigNumState\* pPrivate, const
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


The function stores the private key *priveKey* and public key *pubKey*
in the cryptosystem context.


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
     - Indicates an error condition if the parameter pointed bypPrivate has memory size smaller than the order *n* of the elliptic curve base point *G*.
   * - ippStsRangeErr   
     - Indicates an error condition if the parameter pointed by pPublic has memory size smaller than the prime *p* of the elliptic curve base point *G*.



