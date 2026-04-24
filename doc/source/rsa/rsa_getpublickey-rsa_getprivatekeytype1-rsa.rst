.. _rsa_getpublickey-privatekeytype1-type2:


RSA_GetPublicKey, RSA_GetPrivateKeyType1, RSA_GetPrivateKeyType2
================================================================


Extracts key components from an RSA key context.


Syntax
------


IppStatus ippsRSA_GetPublicKey(IppsBigNumState\* pModulus,
IppsBigNumState\* pPublicExp, const IppsRSAPublicKeyState\* pKey);


IppStatus ippsRSA_GetPrivateKeyType1(IppsBigNumState\* pModulus,
IppsBigNumState\* pPrivateExp, const IppsRSAPrivateKeyState\* pKey);


IppStatus ippsRSA_GetPrivateKeyType2(IppsBigNumState\* pFactorP,
IppsBigNumState\* pFactorQ, IppsBigNumState\* pCrtExpP,
IppsBigNumState\* pCrtExpQ, IppsBigNumState\* pInverseQ, const
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
     -  The ``dP`` and ``dQ`` components of the quintuple (``p,q,dP,dQ,qInv``).
   * -     pInverseQ
     -  The ``qInv`` component of the quintuple (``p,q,dP,dQ,qInv``).
   * -     pKey
     -  Pointer to the IppsRSAPublicKeyState or IppsRSAPrivateKeyState context.




Description
-----------


The RSA_GetPublicKey function extracts components of the RSA public key
(``n``, ``e``) from the IppsRSAPublicKeyState context. The
RSA_GetPrivateKeyType1 and RSA_GetPrivateKeyType2 functions extract
components of the RSA private key of the respective type from the
IppsRSAPrivateKeyState context.


To extract key components selectively, set pointers to the key
components that do not need to be extracted to NULL.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -      Indicates no error. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -      Indicates an error condition if any of the specified pointers is NULL.
   * -     ippStsContextMatchErr
     -     Indicates an error condition if any of the context parameters does not match the operation.
   * -     ippStsSizeErr
     -     Indicates an error condition if the bit length of any specified key component is not sufficient to hold the value.
   * -     ippStsIncompleteContextErr
     -     Indicates an error condition if the public or private key is not set up.


.. note:: While you can set up the public key or type 1 private key in a call to ``RSA_SetPublicKey`` or ``RSA_SetPrivateKeyType1``, respectively, you can set up the type 2 private key in a call to either ``RSA_SetPrivateKeyType2`` or ``RSA_GenerateKeys``.


.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsa_generatekeys`
