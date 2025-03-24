.. _lms-pub-key-get-size:

Get Size Of LMS Public Key
==========================

Get the LMS public key state size (bytes).

Syntax
------

.. code:: cpp

    IppStatus ippsLMSSPublicKeyStateGetSize (Ipp32s* pSize, const IppsLMSAlgoType OIDAlgo);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pSize
     - Pointer to the public key state size.
   * - OIDAlgo
     - LMS Algorithm ID. It defines a set of LMS parameters.
       See :ref:`Supported LMS Algorithms <lms-enum>` for more information.

Description
-----------

This function gets the size of the public key state that is defined by ``OIDAlgo``.
The result is stored to ``*pSize``.

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
     - ``pSize`` is a NULL pointer.
   * - ippStsBadArgErr
     - ``OIDAlgo.lmotsOIDAlgo < the minimum value for IppsLMOTSAlgo``,
       ``OIDAlgo.lmotsOIDAlgo > the maximum value for IppsLMOTSAlgo``,
       ``OIDAlgo.prmLmsAlg < the minimum value for IppsLMSAlgo`` or
       ``OIDAlgo.prmLmsAlg > the maximum value for IppsLMSAlgo``.
