.. _lms-init-sig-state:

Initialize LMS Signature State
==============================

Syntax
------

.. code:: cpp

    IppStatus ippsLMSInitSignature (const IppsLMSAlgoType OIDAlgo, IppsLMSSignatureState* pSign);

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
   * - pSign
     - Pointer to the ``IppsLMSSignatureState`` context.
       Size is greater or equal to the value returned by
       the :ref:`ippsLMSSignatureStateGetSize <lms-states-get-size>` function.

Description
-----------

This function initializes the LMS signature state.

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
     - ``pSign`` is a NULL pointer.
   * - ippStsBadArgErr
     - ``OIDAlgo.lmotsOIDAlgo < the minimum value for IppsLMOTSAlgo``,
       ``OIDAlgo.lmotsOIDAlgo > the maximum value for IppsLMOTSAlgo``,
       ``OIDAlgo.prmLmsAlg < the minimum value for IppsLMSAlgo`` or
       ``OIDAlgo.prmLmsAlg > the maximum value for IppsLMSAlgo``.
