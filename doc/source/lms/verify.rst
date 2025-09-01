.. _lms-verify:

LMS Verification
================

Performs the LMS verification.

Syntax
------

.. code:: cpp

    IppStatus ippsLMSVerify (const Ipp8u* pMsg,
                             const Ipp32u msgLen,
                             const IppsLMSSignatureState* pSign,
                             int* pIsSignValid,
                             const IppsLMSPublicKeyState* pKey,
                             Ipp8u* pBuffer);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pMsg
     - Pointer to the message that have been signed.
   * - msgLen
     - Message length.
   * - pSign
     - Pointer to the ``IppsLMSSignatureState`` context for each verification operation.
       Size is greater or equal to the value returned by
       the :ref:`ippsLMSSignatureStateGetSize <lms-sig-get-size>` function.
   * - pIsSignValid
     - Pointer to the verification result.
   * - pKey
     - Pointer to the ``IppsLMSPublicKeyState`` context for each verification operation.
       Size is greater or equal to the value returned by
       the :ref:`ippsLMSPublicKeyStateGetSize <lms-pub-key-get-size>` function.
   * - pBuffer
     - Pointer to the temporary buffer. Size is greater or equal to
       the value returned by the :ref:`ippsLMSVerifyBufferGetSize <lms-buffer-get-size>` function.

Description
-----------

This function verifies the signature generated using LMS.

``pIsSignValid`` is an output parameter.
If ``*pIsSignValid == 1`` then the LMS signature is valid.
If ``*pIsSignValid == 0`` then the LMS signature is invalid.

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
     - wrong LMS or LM-OTS parameters inside ``pSign`` and ``pKey``
       or ``q`` is incorrect.
   * - ippStsContextMatchErr
     - ``pSign`` or ``pKey`` contexts are invalid.
   * - ippStsLengthErr
     - ``msgLen < 1`` or
       ``msgLen < IPP_MAX_32S - (22 + n)``,
       where ``n`` is the LM-OTS parameter.
