.. _xmss-init-sig-state:

Initialize XMSS Signature State
===============================

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSInitSignature (IppsXMSSAlgo OIDAlgo, IppsXMSSSignatureState* pSign);

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
   * -     pSign
     -  Pointer to the ``IppsXMSSSignatureState`` context.
        Size is greater or equal to the value returned by ``ippsXMSSSignatureStateGetSize``.

Description
-----------

This function initializes the XMSS signature state.
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
    |        authorization path       | h * n bytes
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
     -     ``pSign`` is a NULL pointer.
   * -     ippStsBadArgErr
     -     ``OIDAlgo < 1`` or ``OIDAlgo > the maximum value for IppsXMSSAlgo``.
