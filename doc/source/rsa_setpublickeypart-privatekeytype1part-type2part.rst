.. _rsa_setpublickeypart-privatekeytype1part-type2part:

RSA_SetPublicKeyPart, RSA_SetPrivateKeyType1Part, RSA_SetPrivateKeyType2Part
============================================================================

Set up individual components of an RSA key in the existing RSA key context.

Syntax
------

IppStatus ippsRSA_SetPublicKeyPart(IppRSAKeyTag keyTag, const
IppsBigNumState\* pValue, IppsRSAPublicKeyState\* pKey);

IppStatus ippsRSA_SetPrivateKeyType1Part(IppRSAKeyTag keyTag, const
IppsBigNumState\* pValue, IppsRSAPrivateKeyState\* pKey);

IppStatus ippsRSA_SetPrivateKeyType2Part(IppRSAKeyTag keyTag, const
IppsBigNumState\* pValue, IppsRSAPrivateKeyState\* pKey);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -     keyTag
     -  Specifies which component of the key to set. See table below for valid values per function.
   * -     pValue
     -  Pointer to the big number containing the component value to be set.
   * -     pKey
     -  Pointer to the IppsRSAPublicKeyState or IppsRSAPrivateKeyState context.

Valid keyTag Values
-------------------

.. list-table::
   :header-rows: 1

   * -     Function
     -  Valid keyTag Values
     -  Description
   * -     RSA_SetPublicKeyPart
     -  ``ippRSAkeyN``
     -  RSA modulus ``n``
   * -     
     -  ``ippRSAkeyE``
     -  RSA public exponent ``e``
   * -     RSA_SetPrivateKeyType1Part
     -  ``ippRSAkeyN``
     -  RSA modulus ``n``
   * -     
     -  ``ippRSAkeyD``
     -  RSA private exponent ``d``
   * -     RSA_SetPrivateKeyType2Part
     -  ``ippRSAkeyP``
     -  First prime factor ``p``
   * -     
     -  ``ippRSAkeyQ``
     -  Second prime factor ``q``
   * -     
     -  ``ippRSAkeyDp``
     -  CRT exponent ``dP`` = ``d`` mod (``p``-1)
   * -     
     -  ``ippRSAkeyDq``
     -  CRT exponent ``dQ`` = ``d`` mod (``q``-1)
   * -     
     -  ``ippRSAkeyQinv``
     -  CRT coefficient ``qInv`` = ``q``\ :sup:`-1` mod ``p``

Description
-----------

These functions provide component-by-component setup of RSA keys, offering
greater flexibility compared to setting all components at once.

The RSA_SetPublicKeyPart function sets up individual components of the RSA
public key (``n``, ``e``) in the IppsRSAPublicKeyState context. Components
can be set in any order.

The RSA_SetPrivateKeyType1Part function sets up individual components of
the RSA type 1 private key (``n``, ``d``) in the IppsRSAPrivateKeyState
context. Components can be set in any order.

The RSA_SetPrivateKeyType2Part function sets up individual components of
the RSA type 2 private key in the IppsRSAPrivateKeyState context with the
following behavior:

- Components can be set in any order
- When both prime factors ``p`` and ``q`` and CRT components (``dP``, ``dQ``, ``qInv``) are set, the modulus ``n`` = ``p`` x ``q`` is automatically computed


.. note::

   For setting all key components at once, use the corresponding batch functions: :ref:`RSA_SetPublicKey, RSA_SetPrivateKeyType1, RSA_SetPrivateKeyType2 <rsa_setpublickey-privatekeytype1-type2>`.


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
   * -     ippStsBadArgErr
     -  Indicates an error condition if the keyTag parameter is invalid for the respective key type.
   * -     ippStsSizeErr
     -  Indicates an error condition if the bit length of the component value exceeds the maximum allowed size for that component.
   * -     ippStsOutOfRangeErr
     -  Indicates an error condition if the component value is not positive.


