.. _dlpgenkeypair:


DLPGenKeyPair
=============


Generates a private key and computes public keys of the DL-based
cryptosystem over GF(p).


Syntax
------


IppStatus ippsDLPGenKeyPair(IppsBigNumState\* pPrivate,
IppsBigNumState\* pPublic, IppsDLPState\* pCtx, IppBitSupplier rndFunc,
void\* pRndParam);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * - pPrivate
     - Pointer to the private key *privKey*.
   * - pPublic
     - Pointer to the public key *pubKey*.
   * - pCtx
     - Pointer to the cryptosystem context.
   * - rndFunc
     - Specified Random Generator.
   * - pRndParam
     - Pointer to the Random Generator context.




Description
-----------


The function generates a private key *privKey* and computes a public key
*pubKey* of the DL-based cryptosystem. The function employs specified
rndFunc Random Generator to generate a pseudorandom private key. The
value of the private key *privKey* is a random number that lies in the
range of [2,\ *R*-2].


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
   * - ippStsRangeErr
     - Indicates an error condition if any of the Big Numbers specified by pPrivate and pPublic is too small for the DL key.



