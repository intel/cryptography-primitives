.. _lms-init-key-state:

Initialize LMS Key Pair State
=============================

Syntax
------

.. code:: cpp

    IppStatus ippsLMSInitKeyPair (const IppsLMSAlgoType OIDAlgo,
                                  Ipp32s extraBufSize,
                                  IppsLMSPrivateKeyState* pPrvKey,
                                  IppsLMSPublicKeyState* pPubKey);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * -  OIDAlgo
     -  LMS Algorithm ID. It defines a set of LMS parameters.
        See :ref:`Supported LMS Algorithms <lms-enum>` for more information.
   * -  extraBufSize
     -  Size of extra buffer allocated as part of the private key state.
        It is useful for storing tree nodes that are near the root. The larger this value,
        the less execution time for signature generation.
   * -  pPrvKey
     -  Pointer to the ``IppsLMSPrivateKeyState`` context.
        Size is greater or equal to the value returned by
        the :ref:`ippsLMSPrivateKeyStateGetSize <lms-states-get-size>` function.
   * -  pPubKey
     -  Pointer to the ``IppsLMSPublicKeyState`` context.
        Size is greater or equal to the value returned by
        the :ref:`ippsLMSPublicKeyStateGetSize <lms-states-get-size>` function.

.. note::

   ``extraBufSize`` must be a multiple of the LMS parameter ``m``.
   If it is not, the value will be reduced to the nearest lower multiple of ``m``.
   Example: if ``extraBufSize == 3 * m + 2`` then
   ``extraBufSize == 3 * m`` will be used inside the implementation
   and the function will output the ``ippStsSizeWrn`` warning status.

Description
-----------

This function initializes states for private and public keys.

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
     - Indicates no error. All single operations executed without errors. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pPrvKey`` or ``pPubKey`` is a NULL pointer.
   * - ippStsLengthErr
     - ``extraBufSize < 0``.
   * - ippStsBadArgErr
     - ``OIDAlgo.lmotsOIDAlgo < the minimum value for IppsLMOTSAlgo``,
       ``OIDAlgo.lmotsOIDAlgo > the maximum value for IppsLMOTSAlgo``,
       ``OIDAlgo.prmLmsAlg < the minimum value for IppsLMSAlgo`` or
       ``OIDAlgo.prmLmsAlg > the maximum value for IppsLMSAlgo``.
