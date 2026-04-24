.. _rsa_setpublickey-privatekeytype1-type2:

RSA_SetPublicKey, RSA_SetPrivateKeyType1, RSA_SetPrivateKeyType2
================================================================


Set up an RSA key in the existing RSA key context.


Syntax
------


IppStatus ippsRSA_SetPublicKey(const IppsBigNumState\* pModulus, const
IppsBigNumState\* pPublicExp, IppsRSAPublicKeyState\* pKey);


IppStatus ippsRSA_SetPrivateKeyType1(const IppsBigNumState\* pModulus,
const IppsBigNumState\* pPrivateExp, IppsRSAPrivateKeyState\* pKey);


IppStatus ippsRSA_SetPrivateKeyType2(const IppsBigNumState\* pFactorP,
const IppsBigNumState\* pFactorQ, const IppsBigNumState\* pCrtExpP,
const IppsBigNumState\* pCrtExpQ, const IppsBigNumState\* pInverseQ,
IppsRSAPrivateKeyState\* pKey);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pModulus
     -  The composite RSA modulus ``n``.
   * -     pPublicExp
     -  The ``e`` component of the RSA public key.
   * -     pPrivateExp
     -  The ``d`` component of the type 1 RSA private key.
   * -     pFactorP, pFactorQ
     -  The ``p`` and ``q`` factors of the RSA modulus ``n`` = ``p``\ \*\ ``q``.
   * -     pCrtExpP, pCrtExpQ
     -  The ``dP`` and ``dQ`` components of the quintuple (``p,q,dP,dQ,qInv``), which defines a type 2 private key.
   * -     pInverseQ
     -  The ``qInv`` component of the quintuple (``p,q,dP,dQ,qInv``).
   * -     pKey
     -  Pointer to the IppsRSAPublicKeyState or IppsRSAPrivateKeyState context.




Description
-----------


The RSA_SetPublicKey function sets up the RSA public key (``n``, ``e``)
in the IppsRSAPublicKeyState context, that is, copies the ``n`` and
``e`` components supplied by the user into the context.


The RSA_SetPrivateKeyType1 function sets up the RSA type 1 private key
(``n``, ``d``) in the IppsRSAPrivateKeyState context, that is, copies
the ``n`` and ``d`` components supplied by the user into the context.


The RSA_SetPrivateKeyType2 function sets up the RSA type 2 private key
(``p,q,dP,dQ,qInv``) in the IppsRSAPrivateKeyState context, that is,
copies user-supplied ``p`` and ``q`` factors of the RSA composite
modulus into the context, computes the rest of the key components, and
copies them into the context:


-  ``dP`` = ``q`` mod (``p``-1)


-  ``dQ`` = ``p`` mod (``q``-1)


-  ``qInv`` = 1/``q`` mod ``p``


.. note::

   Component-by-component alternatives are available: :ref:`RSA_SetPublicKeyPart, RSA_SetPrivateKeyType1Part, RSA_SetPrivateKeyType2Part <rsa_setpublickeypart-privatekeytype1part-type2part>`. These functions allow individual key components to be set in any order with immediate validation.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -  Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr
     -  Indicates an error condition if any of the context parameters does not match the operation.
   * -     ippStsSizeErr
     -     Indicates an error condition if the bit length of a key component specified by the pModulus, pPublicExp, pPrivateExp, pFactorP, or pFactorQ pointer exceeds the bit length specified at the initialization.
   * -     ippStsOutOfRangeErr
     -  Indicates an error condition if any key component is not positive.



