.. _ml-dsa-init:

ippsMLDSA_Init
=================

Initializes ``IppsMLDSAState`` for the further ML-DSA computations.

Syntax
------
.. code:: cpp

    IppStatus ippsMLDSA_Init(IppsMLDSAState* pMLDSACtx,
                             Ipp32s maxMessageLength,
                             IppsMLDSAParamSet schemeType);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pMLDSACtx
     - Pointer to the ML-DSA state.
   * - maxMessageLength
     - Maximum message length in bytes. The parameter is used to calculate the size of the internal
       buffers. The maximum message length should be less than 2^32 bytes - number
       of bytes required for temporary buffers. Size of such buffers can be obtained using
       :ref:`API to query working buffers size <ml-dsa-buffers-get-size>`. If the context is used exclusively for :ref:`ippsMLDSA_Verify_Mu <ml-dsa-verify>`, which does not depend on the message length, the ``IPPCP_MLDSA_NO_MESSAGE`` macro can be passed as a dummy value.
   * - schemeType
     - Parameter specifying the scheme type. See
       :ref:`Supported ML-DSA parameters <ml-dsa-params>` for more information.

Description
-----------

The function initializes ``IppsMLDSAState`` for the further ML-DSA computations.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   The API family is supported in experimental mode. To use the functions, users need to define
   the ``IPPCP_PREVIEW_ML_DSA`` macro before including the ``ippcp.h`` header file. See
   :ref:`Preview Features <experimental>` for more details.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - ``pMLDSACtx`` is a ``NULL`` pointer.
   * - ippStsBadArgErr
     - ``schemeType`` is not supported.
   * - ippStsLengthErr
     - ``maxMessageLength`` is less than 1 (and not equal to ``IPPCP_MLDSA_NO_MESSAGE``) or greater than the allowed maximum.
