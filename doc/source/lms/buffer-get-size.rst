.. _lms-buffer-get-size:

Get Size Of Temporary Buffer
============================

Get the size of the temporary buffer that is required for
the ``ippsLMSVerify`` function (bytes).

Syntax
------

.. code:: cpp

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
     - Pointer to the signature state size.
   * - maxMessageLength
     - Maximum length of the message that needs to be verified.
       It can be the maximum length of all messages that can potentially
       be passed to the verification function.
   * - OIDAlgo
     - LMS Algorithm ID. It defines a set of LMS parameters.
       See :ref:`Supported LMS Algorithms <lms-enum>` for more information.

Description
-----------

This function gets the size of the temporary buffer.
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
