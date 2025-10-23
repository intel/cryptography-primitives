.. _lms-buffer-get-size:

Get Size Of Temporary Buffer
============================

Get the size for the temporary buffer (bytes).

Syntax
------

.. code:: cpp

    IppStatus ippsLMSBufferGetSize (Ipp32s* pSize,
                                    Ipp32s maxMessageLength,
                                    const IppsLMSAlgoType OIDAlgo);

    IppStatus ippsLMSKeyGenBufferGetSize (Ipp32s* pSize, const IppsLMSAlgoType OIDAlgo);

    IppStatus ippsLMSSignBufferGetSize (Ipp32s* pSize,
                                        Ipp32s maxMessageLength,
                                        const IppsLMSAlgoType OIDAlgo);

    IppStatus ippsLMSVerifyBufferGetSize (Ipp32s* pSize,
                                          Ipp32s maxMessageLength,
                                          const IppsLMSAlgoType OIDAlgo);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pSize
     - Pointer to the temporary buffer size.
   * - maxMessageLength
     - Maximum length of the message.
       It can be the maximum length of all messages that can potentially
       be passed to the corresponding function, e.g.
       ``ippsLMSSign``, ``ippsLMSKeyGen`` or ``ippsLMSVerify``.
   * - OIDAlgo
     - LMS Algorithm ID. It defines a set of LMS parameters.
       See :ref:`Supported LMS Algorithms <lms-enum>` for more information.

Description
-----------

.. note::

   ``ippsLMSBufferGetSize`` is deprecated. Please refer to
   :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

``ippsLMSKeyGenBufferGetSize`` gets the size of the temporary buffer required for ``ippsLMSKeyGen``.

``ippsLMSSignBufferGetSize`` gets the size of the temporary buffer required for ``ippsLMSSign``.

``ippsLMSVerifyBufferGetSize`` gets the size of the temporary buffer required for ``ippsLMSVerify``.

The result is stored to ``*pSize``.


.. note::

   .. rubric:: Important
      :class: NoteTipHead

   You need to enable the ``IPPCP_PREVIEW_LMS`` macro to use the feature.
   For more information, see :ref:`Preview Features <experimental>`.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pSize`` is a NULL pointer.
   * - ippStsLengthErr
     - ``maxMessageLength < 1`` or
       ``maxMessageLength < IPP_MAX_32S - (22 + n)``,
       where ``n`` is the LM-OTS parameter.
   * - ippStsBadArgErr
     - ``OIDAlgo.lmotsOIDAlgo < the minimum value for IppsLMOTSAlgo``,
       ``OIDAlgo.lmotsOIDAlgo > the maximum value for IppsLMOTSAlgo``,
       ``OIDAlgo.prmLmsAlg < the minimum value for IppsLMSAlgo`` or
       ``OIDAlgo.prmLmsAlg > the maximum value for IppsLMSAlgo``.
