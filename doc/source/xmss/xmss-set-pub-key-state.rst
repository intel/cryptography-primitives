.. _xmss-set-pub-key-state:

Set XMSS Public Key State
=========================

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSSetPublicKeyState (IppsXMSSAlgo OIDAlgo,
                                         const Ipp8u* pRoot,
                                         const Ipp8u* pSeed,
                                         IppsXMSSPublicKeyState* pState);

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
   * -     pRoot
     -  Pointer to the XMSS public key root.
   * -     pSeed
     -  Pointer to the XMSS public key seed.
   * -     pState
     -  Pointer to the XMSS public key state.

Description
-----------

This function sets the public key state.
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
     -     Any of the input parameters is a NULL pointer.
   * -     ippStsBadArgErr
     -     ``OIDAlgo < 1`` or ``OIDAlgo > the maximum value for IppsXMSSAlgo``.
