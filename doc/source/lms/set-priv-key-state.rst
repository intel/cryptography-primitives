.. _lms-set-priv-key-state:

Set LMS Private Key State
=========================

Syntax
------

.. code:: cpp

    IppStatus ippsLMSSetPrivateKeyState (const IppsLMSAlgoType OIDAlgo,
                                         const Ipp32u q,
                                         const Ipp8u* pSecretSeed,
                                         const Ipp8u* pI,
                                         const Ipp8u* pExtraBuf,
                                         const Ipp32s extraBufSize,
                                         IppsLMSPrivateKeyState* pState);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - OIDAlgo
     - LMS Algorithm ID. It defines a set of LMS parameters.
       See :ref:`Supported LMS Algorithms <lms-enum>` for more information.
   * - q
     - Leaf number (signature counter). Must be less than ``2^h``,
       where ``h`` is the LMS tree height parameter.
   * - pSecretSeed
     - Pointer to the LMS private key secret seed (``m`` bytes,
       where ``m`` is the LMS parameter).
   * - pI
     - Pointer to the LMS 16-byte private key identifier ``I``.
   * - pExtraBuf
     - Pointer to the extra buffer data. Can be ``NULL`` if ``extraBufSize`` is 0.
   * - extraBufSize
     - Size of the extra buffer data, in bytes.
   * - pState
     - Pointer to the LMS private key state.

Description
-----------

This function sets the LMS private key state.
It writes the algorithm types, the signature counter ``q``, the secret seed,
the identifier ``I`` and the optional extra buffer content into the provided
private key state.

The scheme of the private key is shown below:

.. code:: cpp

    +---------------------------------+
    |           IppsLMSAlgo           | 4 bytes
    +---------------------------------+
    |          IppsLMOTSAlgo          | 4 bytes
    +---------------------------------+
    |                q                | 4 bytes
    +---------------------------------+
    |           secret seed           | m bytes
    +---------------------------------+
    |                I                | 16 bytes
    +---------------------------------+
    |           extra buffer          | extraBufSize bytes
    +---------------------------------+

``m`` is an LMS parameter.

.. note::

   ``extraBufSize`` must be a multiple of the LMS parameter ``m``.
   If it is not, the value will be reduced to the nearest lower multiple of ``m``
   inside the implementation.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   This is a :ref:`Preview Feature <experimental>`.
   You need to enable the ``IPPCP_PREVIEW_LMS`` macro to use the feature.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pSecretSeed``, ``pI`` or ``pState`` is a NULL pointer,
       or ``pExtraBuf`` is a NULL pointer when ``extraBufSize > 0``.
   * - ippStsLengthErr
     - ``extraBufSize < 0``.
   * - ippStsBadArgErr
     - ``OIDAlgo.lmotsOIDAlgo < the minimum value for IppsLMOTSAlgo``,
       ``OIDAlgo.lmotsOIDAlgo > the maximum value for IppsLMOTSAlgo``,
       ``OIDAlgo.prmLmsAlg < the minimum value for IppsLMSAlgo``,
       ``OIDAlgo.prmLmsAlg > the maximum value for IppsLMSAlgo`` or
       ``q`` is out of valid range (``q >= 2^h``).