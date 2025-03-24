.. _lms-set-sig-state:

Set LMS Signature State
=======================

Syntax
------

.. code:: cpp

    IppStatus ippsLMSSetSignatureState (const IppsLMSAlgoType OIDAlgo,
                                        Ipp32u q,
                                        const Ipp8u* pC,
                                        const Ipp8u* pY,
                                        const Ipp8u* pAuthPath,
                                        IppsLMSSignatureState* pState);

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
     - Index of the LMS tree leaf.
   * - pC
     - Pointer to the random string ``C``.
   * - pY
     - Pointer to ``Y`` that is a part of the LM-OTS string.
   * - pAuthPath
     - Pointer to the LMS authorization path.
   * - pState
     - Pointer to the LMS signature state.

Description
-----------

This function sets the LMS signature state.
The scheme of the signature is shown below:

.. code:: cpp

    +---------------------------------+
    |                q                | 4 bytes
    +---------------------------------+
    |          LM-OTS signature       | 4 + n * (p + 1) bytes
    +---------------------------------+
    |           IppsLMSAlgo           | 4 bytes
    +---------------------------------+
    |        authorisation path       | h * m bytes
    +---------------------------------+

``m``, ``h`` are LMS parameters.

The scheme of the LM-OTS signature is shown below:

.. code:: cpp

    +---------------------------------+
    |          IppsLMOTSAlgo          | 4 bytes
    +---------------------------------+
    |                C                | n bytes
    +---------------------------------+
    |                Y                | p * n bytes
    +---------------------------------+

``n``, ``p`` are LM-OTS parameters.

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
       ``OIDAlgo.prmLmsAlg < the minimum value for IppsLMSAlgo``,
       ``OIDAlgo.prmLmsAlg > the maximum value for IppsLMSAlgo`` or
       ``q`` is incorrect.
