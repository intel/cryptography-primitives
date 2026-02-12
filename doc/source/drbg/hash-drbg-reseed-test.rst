.. _hash-drbg-reseed-test:

ippsHashDRBG_ReseedTest
========================

Performs known-answer testing the ``ippsHashDRBG_Reseed`` function on demand.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_ReseedTest(IppsHashDRBG_EntropyInputCtx* pEntrInputCtxTempBuf,
                                      IppsHashDRBGState* pDrbgCtxTempBuf);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pEntrInputCtxTempBuf
     - Pointer to a temporarily allocated buffer used to store the Entropy input context.
   * - pDrbgCtxTempBuf
     - Pointer to a temporarily allocated buffer used to store the Hash DRBG state.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   Separate buffers must be allocated for the Entropy input context and the Hash DRBG state
   and passed to the ``ippsHashDRBG_ReseedTest`` function. Otherwise, the current state of
   working buffers will be corrupted, resulting in incorrect pseudorandom number sequences.

Description
-----------

This function initializes ``pEntrInputCtxTempBuf`` and ``pDrbgCtxTempBuf`` context buffers,
instantiates the Hash DRBG and then performs known-answer testing the ``ippsHashDRBG_Reseed`` function
using the minimum security strength, representative values for the entropy input and additional input,
and the requested prediction resistance.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       The values used during the test produce the expected results.
   * - ippStsNullPtrErr
     - ``pEntrInputCtxTempBuf`` or ``pDrbgCtxTempBuf`` is a NULL pointer.
       The pointer to the buffer that contains the entropy input is NULL.
   * - ippStsContextMatchErr
     - If the Entropy input context identifier or the Hash DRBG identifier doesn't match.
   * - ippStsOutOfRangeErr
     - ``entrInputBufBitsLen < 1``.
   * - ippStsNotSupportedModeErr
     - The CPU does not support the ``RDSEED`` and/or ``RDRAND`` instructions.
   * - ippStsHashOperationErr
     - An error status code was returned during hashing operations.
