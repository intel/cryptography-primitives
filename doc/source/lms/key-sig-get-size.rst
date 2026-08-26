.. _lms-states-get-size:

Get Size Of LMS Keys and Signature States
=========================================

Get the size (bytes) for following LMS states: public key, private key and signature.

Syntax
------

.. code:: cpp

    IppStatus ippsLMSPublicKeyStateGetSize (Ipp32s* pSize, const IppsLMSAlgoType OIDAlgo);

    IppStatus ippsLMSPrivateKeyStateGetSize (Ipp32s* pSize, const IppsLMSAlgoType OIDAlgo, Ipp32s extraBufSize);

    IppStatus ippsLMSSignatureStateGetSize (Ipp32s* pSize, const IppsLMSAlgoType OIDAlgo);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pSize
     - Pointer to the state size.
   * - extraBufSize
     - Size of extra buffer allocated as part of the private key state.
       It is useful for storing tree nodes that are near the root. The larger this value,
       the less execution time for signature generation.
   * - OIDAlgo
     - LMS Algorithm ID. It defines a set of LMS parameters.
       See :ref:`Supported LMS Algorithms <lms-enum>` for more information.

.. note::

   ``extraBufSize`` must be a multiple of the LMS parameter ``m``.
   If it is not, the value will be reduced to the nearest lower multiple of ``m``.
   Example: if ``extraBufSize == 3 * m + 2`` then
   ``extraBufSize == 3 * m`` will be used inside the implementation
   and the function will output the ``ippStsSizeWrn`` warning status.

Description
-----------

``ippsLMSPublicKeyStateGetSize``  gets the size of the public key state that is defined by ``OIDAlgo``.

``ippsLMSPrivateKeyStateGetSize`` gets the size of the private key state.

``ippsLMSSignatureStateGetSize``  gets the size of the signature state.

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
   * - ippStsBadArgErr
     - ``OIDAlgo.lmotsOIDAlgo < the minimum value for IppsLMOTSAlgo``,
       ``OIDAlgo.lmotsOIDAlgo > the maximum value for IppsLMOTSAlgo``,
       ``OIDAlgo.lmsOIDAlgo < the minimum value for IppsLMSAlgo`` or
       ``OIDAlgo.lmsOIDAlgo > the maximum value for IppsLMSAlgo``.
   * - ippStsLengthErr
     - ``extraBufSize < 0``.
   * - ippStsSizeWrn
     - ``extraBufSize`` is not a multiple of the LMS parameter ``m``.
