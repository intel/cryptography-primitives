.. _lms-set-pub-key-state:

Set LMS Public Key State
========================

Syntax
------

.. code:: cpp

    IppStatus ippsLMSSetPublicKeyState (const IppsLMSAlgoType OIDAlgo,
                                        const Ipp8u* pI,
                                        const Ipp8u* pK,
                                        IppsLMSPublicKeyState* pState);

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
   * - pI
     - Pointer to the LMS 16-byte string ``I``.
   * - pK
     - Pointer to the LMS public key ``K`` value.
   * - pState
     - Pointer to the LMS public key state.

Description
-----------

This function sets the public key state.
The scheme of the public key is shown below:

.. code:: cpp

    +---------------------------------+
    |           IppsLMSAlgo           | 4 bytes
    +---------------------------------+
    |          IppsLMOTSAlgo          | 4 bytes
    +---------------------------------+
    |               I                 | 16 bytes
    +---------------------------------+
    |               K                 | n bytes
    +---------------------------------+

``n`` is a LM-OTS parameter.

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
     - Any of the input parameters is a NULL pointer.
   * - ippStsBadArgErr
     - ``OIDAlgo.lmotsOIDAlgo < the minimum value for IppsLMOTSAlgo``,
       ``OIDAlgo.lmotsOIDAlgo > the maximum value for IppsLMOTSAlgo``,
       ``OIDAlgo.prmLmsAlg < the minimum value for IppsLMSAlgo`` or
       ``OIDAlgo.prmLmsAlg > the maximum value for IppsLMSAlgo``.
