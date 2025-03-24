.. _xmss-set-sig-state:

Set XMSS Signature State
========================

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSSetSignatureState (IppsXMSSAlgo OIDAlgo,
                                         Ipp32u idx,
                                         const Ipp8u* r,
                                         const Ipp8u* pOTSSign,
                                         const Ipp8u* pAuthPath,
                                         IppsXMSSSignatureState* pState);

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
   * -     idx
     -  Index of the XMSS tree leaf.
   * -     r
     -  Pointer to the XMSS signature randomness variable.
   * -     pOTSSign
     -  Pointer to the WOTS signature.
   * -     pAuthPath
     -  Pointer to the XMSS authorization path.
   * -     pState
     -  Pointer to the XMSS signature state.

Description
-----------

This function sets the XMSS signature state.
The scheme of the signature is shown below:

.. code:: cpp

    +---------------------------------+
    |                                 |
    |          index idx_sig          | 4 bytes
    |                                 |
    +---------------------------------+
    |                                 |
    |          randomness r           | n bytes
    |                                 |
    +---------------------------------+
    |                                 |
    |     WOTS+ signature sig_ots     | len * n bytes
    |                                 |
    +---------------------------------+
    |                                 |
    |        authorisation path       | h * n bytes
    |                                 |
    +---------------------------------+

``n``, ``len`` are WOTS+ parameters, ``h`` is the XMSS tree height.

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
