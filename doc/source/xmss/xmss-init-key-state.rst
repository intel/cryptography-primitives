.. _xmss-init-key-state:

Initialize XMSS Key Pair State
==============================

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSInitKeyPair (IppsXMSSAlgo OIDAlgo,
                                   IppsXMSSPrivateKeyState* pPrvKey,
                                   IppsXMSSPublicKeyState* pPubKey);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -     OIDAlgo
     -  XMSS Algorithm ID. It defines a set of XMSS parameters.
        See :ref:`Supported XMSS Algorithms <xmss-enum>` for more information.
   * -     pPrvKey
     -  Pointer to the ``IppsXMSSPrivateKeyState`` context.
        Size is greater or equal to the value returned by ``ippsXMSSPrivateKeyStateGetSize``.
   * -     pPubKey
     -  Pointer to the ``IppsXMSSPublicKeyState`` context.
        Size is greater or equal to the value returned by ``ippsXMSSPublicKeyStateGetSize``.
        The pointer can be a NULL pointer. In this case only ``pPrvKey`` is initialized.

Description
-----------

This function initializes states for private and public keys.
The scheme of the private key is shown below:

.. code:: cpp

    +---------------------------------+
    |          algorithm OID          |
    +---------------------------------+
    |        private key index        | 4 bytes
    +---------------------------------+
    |                                 |
    |        private key seed         | n bytes
    |                                 |
    +---------------------------------+
    |                                 |
    |           SK_PRF key            | n bytes
    |                                 |
    +---------------------------------+
    |                                 |
    |           root node             | n bytes
    |                                 |
    +---------------------------------+
    |                                 |
    |        public key seed          | n bytes
    |                                 |
    +---------------------------------+

The scheme of the public key is shown below:

.. code:: cpp

    +---------------------------------+
    |          algorithm OID          |
    +---------------------------------+
    |                                 |
    |            root node            | n bytes
    |                                 |
    +---------------------------------+
    |                                 |
    |              SEED               | n bytes
    |                                 |
    +---------------------------------+

``n`` is a WOTS+ parameter.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   This is a :ref:`Preview Feature <experimental>`.
   You need to enable the ``IPPCP_PREVIEW_XMSS`` macro to use the feature.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -     Indicates no error. All single operations executed without errors. Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -     ``pPrvKey`` is a NULL pointer.
   * -     ippStsBadArgErr
     -     ``OIDAlgo < 1`` or ``OIDAlgo > the maximum value for IppsXMSSAlgo``.
