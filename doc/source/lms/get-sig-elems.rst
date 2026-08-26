.. _lms-get-sig-elems:

Get LMS Signature Elements
==========================

Syntax
------

.. code:: cpp

    IppStatus ippsLMSGetSignatureElems (IppsLMSAlgoType* pLmsType,
                                        Ipp32u* pQ,
                                        Ipp8u* pC,
                                        Ipp8u* pY,
                                        Ipp8u* pAuthPath,
                                        const IppsLMSSignatureState* pState);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pLmsType
     - Pointer to the output LMS Algorithm ID (``lmotsOIDAlgo`` and ``lmsOIDAlgo``),
       or ``NULL``. See :ref:`Supported LMS Algorithms <lms-enum>` for more information.
   * - pQ
     - Pointer to the output index of the LMS tree leaf ``q``, or ``NULL``.
   * - pC
     - Pointer to the output buffer for the random string ``C`` (``n`` bytes),
       or ``NULL``.
   * - pY
     - Pointer to the output buffer for ``Y`` that is a part of the LM-OTS string
       (``n * p`` bytes), or ``NULL``.
   * - pAuthPath
     - Pointer to the output buffer for the LMS authorization path (``h * m`` bytes),
       or ``NULL``.
   * - pState
     - Pointer to the LMS signature state.

Description
-----------

This function extracts the components of the LMS signature state that was
previously set with :ref:`ippsLMSSetSignatureState <lms-set-sig-state>`.
See :ref:`Set LMS Signature State <lms-set-sig-state>` for the scheme of the
signature and the scheme of the LM-OTS signature.

Every output pointer except ``pState`` is optional: pass ``NULL`` for any
component that is not needed and it will be skipped, leaving the caller's buffer
untouched. A single call can therefore return one, several, or all components at
once. Each provided (non-``NULL``) buffer must be large enough for its component
according to the algorithm parameter set stored in the state.

.. note::

   .. rubric:: Usage restriction
      :class: NoteTipHead

   Call this function only on a state that has been fully populated by
   :ref:`ippsLMSSign <lms-sign>` or by
   :ref:`ippsLMSSetSignatureState <lms-set-sig-state>`. A state that was only
   initialized with :ref:`ippsLMSInitSignature <lms-init-sig-state>` contains the
   algorithm parameters but not yet valid signature values, so the extracted
   components (``q``, ``C``, ``Y``, ``AuthPath``) will be undefined.

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
     - ``pState`` is a NULL pointer.
   * - ippStsContextMatchErr
     - The ``pState`` context is invalid.
   * - ippStsBadArgErr
     - The state holds an unsupported ``lmotsOIDAlgo`` or ``lmsOIDAlgo``.
