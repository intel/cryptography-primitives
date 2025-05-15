.. _xmss-states-get-size:

Get Size Of XMSS Keys and Signature States
==========================================

Get the size (bytes) for following XMSS states: public key, private key and signature.

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSPublicKeyStateGetSize (Ipp32s* pSize, IppsXMSSAlgo OIDAlgo);

    IppStatus ippsXMSSPrivateKeyStateGetSize (Ipp32s* pSize, IppsXMSSAlgo OIDAlgo);

    IppStatus ippsXMSSSignatureStateGetSize (Ipp32s* pSize, IppsXMSSAlgo OIDAlgo);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -     pSize
     -  Pointer to the state size.
   * -     OIDAlgo
     -  XMSS Algorithm ID. It defines a set of XMSS parameters.
        See :ref:`Supported XMSS Algorithms <xmss-enum>` for more information.

Description
-----------

``ippsXMSSPublicKeyStateGetSize``  gets the size of the public key state that is defined by ``OIDAlgo``.

``ippsXMSSPrivateKeyStateGetSize`` gets the size of the private key state.

``ippsXMSSSignatureStateGetSize``  gets the size of the signature state.

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
