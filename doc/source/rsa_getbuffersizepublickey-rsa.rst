.. _rsa_getbuffersizepublickey-privatekey:


RSA_GetBufferSizePublicKey, RSA_GetBufferSizePrivateKey
=======================================================


Get the size of a temporary scratch buffer for future use in RSA
operations.


Syntax
------


IppStatus ippsRSA_GetBufferSizePublicKey(int\* pBufferSize, const
IppsRSAPublicKeyState\* pKey);


IppStatus ippsRSA_GetBufferSizePrivateKey(int\* pBufferSize, const
IppsRSAPrivateKeyState\* pKey);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pBufferSize
     -  Pointer to the size of a temporary buffer.
   * -     pKey
     -  Pointer to the RSA key context.




Description
-----------


These functions get the size of a temporary buffer for future use in
public- or private-key RSA operations, respectively.


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
   * -     ippStsIncompleteContextErr
     - * For RSA_GetBufferSizePublicKey, indicates an error condition if the public key is not set up.
       * For RSA_GetBufferSizePrivateKeyType1, indicates an error condition if the type 1 private key is not set up.


.. note:: You can set up the public key or type 1 private key in a call to ``RSA_SetPublicKey`` or ``RSA_SetPrivateKeyType1``, respectively. For the ``RSA_GetBufferSizePrivateKeyType2`` function, it suffices to initialize the context for the key in a call to ``RSA_InitPrivateKeyType2``.


.. rubric:: Related Information

* :ref:`rsa_setpublickey-privatekeytype1-type2`
* :ref:`rsa_initpublickey-privatekeytype1-type2`

