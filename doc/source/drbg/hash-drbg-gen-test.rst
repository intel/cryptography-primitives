.. _hash-drbg-gen-test:

ippsHashDRBG_GenTest
=====================

Tests the ``ippsHashDRBG_Gen`` function on demand.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_GenTest(Ipp32u* pRandBuf,
                                   int nBits,
                                   IppsHashDRBG_EntropyInputCtx* pEntrInputCtxTempBuf,
                                   IppsHashDRBGState* pDrbgCtxTempBuf);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pRandBuf
     - Pointer to a buffer used to store the output generated during ``ippsHashDRBG_Gen`` testing.
   * - nBits
     - Number of bits to be generated to test ``ippsHashDRBG_Gen``.
   * - pEntrInputCtxTempBuf
     - Pointer to a temporarily allocated buffer used to store the Entropy input context.
   * - pDrbgCtxTempBuf
     - Pointer to a temporarily allocated buffer used to store the Hash DRBG state.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   - The ``pRandBuf`` buffer size must be at least 128 bytes (or 1024 bits) in size to
     accommodate the pseudorandom data that will be generated. However, ``nBits`` must be
     equal to or less than 1024 bits, which is the maximum number of bits that can be generated.
   - Separate buffers must be allocated for the Entropy input context and the Hash DRBG state
     and passed to the ``ippsHashDRBG_GenTest`` function. Otherwise, the working buffers' current
     state will be corrupted, leading to incorrect pseudorandom number sequences.

Description
-----------

This function tests the ``ippsHashDRBG_Gen`` function using the minimum security strength, representative
values for the entropy input, nonce and personalization string, and the requested prediction resistance.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       The values used during the test produce the expected results.
   * - ippStsNullPtrErr
     - ``pRandBuf``, ``pEntrInputCtxTempBuf``, or ``pDrbgCtxTempBuf`` is a NULL pointer.
       The pointer to the buffer that contains the entropy input is NULL.
   * - ippStsContextMatchErr
     - If the Entropy input context identifier or the Hash DRBG identifier doesn't match.
   * - ippStsOutOfRangeErr
     - ``entrInputBufBitsLen < 1``.
   * - ippStsNotSupportedModeErr
     - The CPU does not support the ``RDSEED`` and/or ``RDRAND`` instructions.
   * - ippStsHashOperationErr
     - An error status code was returned during hashing operations.
