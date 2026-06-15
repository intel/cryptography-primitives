.. _ml-dsa-verify:

ippsMLDSA_Verify, ippsMLDSA_Verify_Mu
=====================================

Uses the public key to verify a digital signature for a given message or a pre-computed message hash (Mu).

Syntax
------
.. code:: cpp

    IppStatus ippsMLDSA_Verify(const Ipp8u* pMsg,
                               const Ipp32s msgLen,
                               const Ipp8u* pCtx,
                               const Ipp32s ctxLen,
                               const Ipp8u* pPubKey,
                               const Ipp8u* pSign,
                               int* pIsSignValid,
                               IppsMLDSAState* pMLDSAState,
                               Ipp8u* pScratchBuffer);

    IppStatus ippsMLDSA_Verify_Mu(const Ipp8u* pMu,
                                  const Ipp8u* pPubKey,
                                  const Ipp8u* pSign,
                                  int* pIsSignValid,
                                  IppsMLDSAState* pMLDSAState,
                                  Ipp8u* pScratchBuffer);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pMsg
     - Pointer to the message that needs to be verified (for ``ippsMLDSA_Verify``).
   * - msgLen
     - Length of the message in bytes (for ``ippsMLDSA_Verify``).
   * - pCtx
     - Pointer to the context, can be ``NULL`` (for ``ippsMLDSA_Verify``). See the Specification of the algorithm for more details.
   * - ctxLen
     - Length of the context in bytes (for ``ippsMLDSA_Verify``).
   * - pMu
     - Pointer to the 64-byte pre-computed Mu hash value (for ``ippsMLDSA_Verify_Mu``).
   * - pPubKey
     - Pointer to the public key.
   * - pSign
     - Pointer to the signature.
   * - pIsSignValid
     - Pointer to the output variable that indicates whether the signature is valid.
       The value is set to 1 if the signature is valid, and 0 if the signature is invalid.
   * - pMLDSAState
     - Pointer to the ML-DSA context.
   * - pScratchBuffer
     - Pointer to the working buffer of size queried by the corresponding size query function
       (:ref:`ippsMLDSA_VerifyBufferGetSize <ml-dsa-buffers-get-size>` or :ref:`ippsMLDSA_Verify_Mu_BufferGetSize <ml-dsa-buffers-get-size>`).

Description
-----------

The functions verify the digital signature using the provided public key.

* ``ippsMLDSA_Verify`` computes the message hash (Mu) internally using the provided message and context. The working buffer should be allocated with a size not less than the one provided by the :ref:`ippsMLDSA_VerifyBufferGetSize <ml-dsa-buffers-get-size>` function.
* ``ippsMLDSA_Verify_Mu`` uses a pre-computed message hash (Mu), which allows bypassing the internal buffering of large messages. The working buffer should be allocated with a size not less than the one provided by the :ref:`ippsMLDSA_Verify_Mu_BufferGetSize <ml-dsa-buffers-get-size>` function.

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
     - ``pMsg``, ``pMu``, ``pPubKey``, ``pSign``, ``pIsSignValid``, ``pMLDSAState`` or ``pScratchBuffer`` is ``NULL``.
   * - ippStsContextMatchErr
     - ``pMLDSAState`` was not initialized.
   * - ippStsMemAllocErr
     - An internal functional error. If this output status appears, update to the latest version
       of the library or contact `Intel <https://github.com/intel/cryptography-primitives/issues>`_.
   * - ippStsLengthErr
     - ``pMLDSAState`` was initialized with ``IPPCP_MLDSA_NO_MESSAGE``, or ``ctxLen < 0`` or ``ctxLen > 255`` or ``msgLen`` is less than 1,
       or the message length is greater than 2^32 bytes minus the number
       of bytes required for temporary buffers. Size of such buffers can be
       obtained using ``ippsMLDSA_VerifyBufferGetSize`` functions (for ``ippsMLDSA_Verify`` only).
   * - ippStsBadArgErr
     - ``ctxLen == 0`` if ``pCtx != NULL`` (for ``ippsMLDSA_Verify`` only).