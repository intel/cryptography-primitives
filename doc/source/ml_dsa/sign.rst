.. _ml-dsa-sign:

ippsMLDSA_Sign
==============

Uses the private key to generate a digital signature for a given message.

Syntax
------
.. code:: cpp

    IppStatus ippsMLDSA_Sign(const Ipp8u* pMsg,
                             const Ipp32s msgLen,
                             const Ipp8u* pCtx,
                             const Ipp32s ctxLen,
                             const Ipp8u* pPrvKey,
                             Ipp8u* pSign,
                             IppsMLDSAState* pMLDSAState,
                             Ipp8u* pScratchBuffer,
                             IppBitSupplier rndFunc,
                             void* pRndParam);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pMsg
     - Pointer to the message that needs to be signed.
   * - msgLen
     - Length of the message in bytes.
   * - pCtx
     - Pointer to the context, can be ``NULL``. See the Specification of the algorithm for more details.
   * - ctxLen
     - Length of the context in bytes.
   * - pPrvKey
     - Pointer to the private key.
   * - pSign
     - Pointer to the produced signature.
   * - pMLDSAState
     - Pointer to the ML-DSA context.
   * - pScratchBuffer
     - Pointer to the working buffer of size queried
       :ref:`ippsMLDSA_SignBufferGetSize <ml-dsa-buffers-get-size>`.
   * - rndFunc
     - Optional function pointer to generate random numbers, can be ``NULL``.
   * - pRndParam
     - Optional parameters for ``rndFunc``, can be ``NULL``.

Description
-----------

The function signs the message using the provided
private key. The size of the signature depends on the selected scheme type and
can be obtained using :ref:`ippsMLDSA_GetInfo <ml-dsa-get-info>` function.
The working buffer should be allocated with the size not less than provided by
:ref:`ippsMLDSA_SignBufferGetSize <ml-dsa-buffers-get-size>` function.

This function internally uses the random number generator (RNG) provided by the user through the ``rndFunc``
parameter, please see :ref:`User's Implementation of a RNG <users-implementation-of-a-pseudorandom-num-gen>`
for more information on creating a customer-defined RNG object. If ``rndFunc`` is ``NULL``, an internal
default random number generator based on the ``RDSEED`` hardware instruction is used.

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
     - ``pMsg``, ``pPrvKey``, ``pSign``, ``pMLDSAState`` or ``pScratchBuffer`` is ``NULL``.
   * - ippStsContextMatchErr
     - ``pMLDSAState`` was not initialized.
   * - ippStsMemAllocErr
     - An internal functional error. If this output status appears, update to the latest version
       of the library or contact `Intel <https://github.com/intel/cryptography-primitives/issues>`_.
   * - ippStsLengthErr
     - ``pMLDSAState`` was initialized with ``IPPCP_MLDSA_NO_MESSAGE``, or ``ctxLen < 0`` or ``ctxLen > 255`` or ``msgLen`` is less than 1,
       or the message length is greater than 2^32 bytes minus the number
       of bytes required for temporary buffers. Size of such buffers can be
       obtained using the ``ippsMLDSA_SignBufferGetSize`` function.
   * - ippStsBadArgErr
     - ``ctxLen == 0`` if ``pCtx != NULL``.
   * - ippStsNotSupportedModeErr
     - Unsupported ``RDSEED`` instruction.
   * - ippStsErr
     - Random bit sequence can't be generated.
   * - An error that may be returned by ``rndFunc``.
     - Problems with the user-defined random number generator.
