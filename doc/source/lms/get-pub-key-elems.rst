.. _lms-get-pub-key-elems:

Get LMS Public Key Elements
===========================

Syntax
------

.. code:: cpp

    IppStatus ippsLMSGetPublicKeyElems (IppsLMSAlgoType* pLmsType,
                                        Ipp8u* pI,
                                        Ipp8u* pT1,
                                        const IppsLMSPublicKeyState* pState);

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
   * - pI
     - Pointer to the output buffer for the LMS 16-byte string ``I``, or ``NULL``.
   * - pT1
     - Pointer to the output buffer for the LMS public key ``T1`` (``m`` bytes) value,
       or ``NULL``.
   * - pState
     - Pointer to the LMS public key state.

Description
-----------

This function extracts the components of the LMS public key state that was
previously set with :ref:`ippsLMSSetPublicKeyState <lms-set-pub-key-state>`.
See :ref:`Set LMS Public Key State <lms-set-pub-key-state>` for the scheme of the
public key.

Every output pointer except ``pState`` is optional: pass ``NULL`` for any
component that is not needed and it will be skipped, leaving the caller's buffer
untouched. A single call can therefore return one, several, or all components at
once. Each provided (non-``NULL``) buffer must be large enough for its component
according to the algorithm parameter set stored in the state.

.. note::

   .. rubric:: Usage restriction
      :class: NoteTipHead

   Call this function only on a state that has been fully populated by
   :ref:`ippsLMSKeyGen <lms-key-gen>` or by
   :ref:`ippsLMSSetPublicKeyState <lms-set-pub-key-state>`. A state that was only
   initialized with :ref:`ippsLMSInitKeyPair <lms-init-key-state>` contains the
   algorithm parameters but not yet valid key values, so the extracted components
   (``I``, ``T1``) will be undefined.

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
     - The state holds an unsupported ``lmsOIDAlgo`` or ``lmotsOIDAlgo``.
