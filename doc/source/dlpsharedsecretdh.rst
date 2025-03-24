.. _dlpsharedsecretdh:

DLPSharedSecretDH
=================


Computes a shared field element by using the Diffie-Hellman scheme.


Syntax
------


IppStatus ippsDLPSharedSecretDH(const IppsBigNumState\* pPrivateA, const
IppsBigNumState\* pPublicB, IppsBigNumState\* pShare, IppsDLPState\*
pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * - pPrivateA   
     - Pointer to your own private key ``privateKeyA``.
   * - pPublicB   
     - Pointer to the public key ``pubKeyB`` belonging to the other party.
   * - pShare   
     - Pointer to the shared secret element ``Share``.
   * - pCtx   
     - Pointer to the cryptosystem context.




Description
-----------


The function computes a shared secret element FG(p)
``pubKeyB``\ :sup:`privateKeyA`\ (``mod``\ ``p``).


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
     - Indicates an error condition if *Share* does not have enough space.



