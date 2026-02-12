.. _hash-drbg-entr-input-init:

ippsHashDRBG_EntropyInputCtxInit
=================================

Initializes the Entropy input context.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_EntropyInputCtxInit(IppsHashDRBG_EntropyInputCtx* pEntrInputCtx,
                                               const int entrInputBufBitsLen,
                                               IppEntropyInputSupplier getEntropyInput);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pEntrInputCtx
     - Pointer to the Entropy input context.
   * - entrInputBufBitsLen
     - The length of the buffer containing the entropy input and the nonce.
   * - getEntropyInput
     - Callback function for supplying the entropy input, providing both an entropy input
       and a nonce during instantiation, and an entropy input during reseeding or whenever
       prediction resistance is requested.

       The callback function must have the following signature:

       ``IppStatus _STDCALL getEntropyInput(Ipp8u* pEntropyInput, int* pEntropyInputBitsLen, const int minEntropyInBits, const int maxBitsLen, const int predictionResistanceRequest)``.

       - ``pEntropyInput`` is a pointer to a byte string containing at least ``minEntropyInBits`` bits of entropy.
       - ``pEntropyInputBitsLen`` is the entropy input buffer length in bits.
       - ``minEntropyInBits`` and ``maxBitsLen`` is the minimum and maximum number bits of the entropy input.
       - ``predictionResistanceRequest`` parameter indicates whether or not prediction resistance is to be provided during the request.

       Refer to the `NIST SP 800-90C <https://csrc.nist.gov/pubs/sp/800/90/c/final>`__ to figure out more about Sources of Randomness.

Description
-----------

The function initializes the ``IppsHashDRBG_EntropyInputCtx`` which encapsulates objects necessary
for entropy input and nonce generation during the Hash DRBG operations.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       Any other value indicates an error.
   * - ippStsNullPtrErr
     - ``pEntrInputCtx`` is a NULL pointer.
   * - ippStsOutOfRangeErr
     - ``entrInputBufBitsLen < 1``.
