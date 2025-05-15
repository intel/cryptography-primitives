.. _xmss-buffer-get-size:

Get Size Of Temporary Buffer
============================

Get the size for the temporary buffer (bytes).

Syntax
------

.. code:: cpp

    IppStatus ippsXMSSBufferGetSize       (Ipp32s* pSize, Ipp32s maxMessageLength, IppsXMSSAlgo OIDAlgo);

    IppStatus ippsXMSSKeyGenBufferGetSize (Ipp32s* pSize, IppsXMSSAlgo OIDAlgo);

    IppStatus ippsXMSSSignBufferGetSize   (Ipp32s* pSize, Ipp32s maxMessageLength, IppsXMSSAlgo OIDAlgo);

    IppStatus ippsXMSSVerifyBufferGetSize (Ipp32s* pSize, Ipp32s maxMessageLength, IppsXMSSAlgo OIDAlgo);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -     pSize
     -  Pointer to the state size.
   * -     maxMessageLength
     -  Maximum length of the message that needs to be verified.
        It can be the maximum of all messages' length that can potentially be passed to the verification function.
   * -     OIDAlgo
     -  XMSS Algorithm ID. It defines a set of XMSS parameters.
        See :ref:`Supported XMSS Algorithms <xmss-enum>` for more information.

Description
-----------

.. note::

   ``ippsXMSSBufferGetSize`` is deprecated. Please refer to
   :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

``ippsXMSSKeyGenBufferGetSize`` gets the size of the temporary buffer required for ``ippsXMSSKeyGen``.

``ippsXMSSSignBufferGetSize`` gets the size of the temporary buffer required for ``ippsXMSSSign``.

``ippsXMSSVerifyBufferGetSize`` gets the size of the temporary buffer required for ``ippsXMSSVerify``.

The result is stored to ``*pSize``.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   You need to enable the ``IPPCP_PREVIEW_XMSS`` macro to use the feature.
   For more information, see :ref:`Preview Features <experimental>`.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * -     ippStsNoErr
     -     Indicates no error. All single operations executed without errors.
           Any other value indicates an error or warning.
   * -     ippStsNullPtrErr
     -     ``pSize`` is a NULL pointer.
   * -     ippStsLengthErr
     -     ``maxMessageLength < 1`` or
           ``maxMessageLength < IPP_MAX_32S - (10 + len) * n``,
           where ``n``, ``len`` are WOTS+ parameters.
   * -     ippStsBadArgErr
     -     ``OIDAlgo < 1`` or ``OIDAlgo > the maximum value for IppsXMSSAlgo``.
