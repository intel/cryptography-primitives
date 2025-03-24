.. _xmss-sig-get-size:

Get Size Of XMSS Signature State
================================

Get the XMSS signature state size (bytes).

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSSignatureStateGetSize (Ipp32s* pSize, IppsXMSSAlgo OIDAlgo);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -     pSize
     -  Pointer to the signature state size.
   * -     OIDAlgo
     -  XMSS Algorithm ID. It defines a set of XMSS parameters.
        See :ref:`Supported XMSS Algorithms <xmss-enum>` for more information.

Description
-----------

This function gets the size of the signature state that is defined by ``OIDAlgo``.
The result is stored to ``*pSize``.

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
     -     ``pSize`` is a NULL pointer.
   * -     ippStsBadArgErr
     -     ``OIDAlgo < 1`` or ``OIDAlgo > the maximum value for IppsXMSSAlgo``.
