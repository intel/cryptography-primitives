.. _hash-drbg-reseed:

ippsHashDRBG_Reseed
====================

Reseeds the Hash DRBG state with new entropy.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_Reseed(const int predictionResistanceRequest,
                                  const Ipp8u* addlInput,
                                  const int addlInputBitsLen,
                                  IppsHashDRBG_EntropyInputCtx* pEntrInputCtx,
                                  IppsHashDRBGState* pDrbgCtx);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - predictionResistanceRequest
     - Indicates whether or not prediction resistance is to be provided
       during the request (whether or not fresh entropy bits are required).
   * - addlInput
     - Pointer to the array containing additional input (optional).
   * - addlInputBitsLen
     - Length of the ``addlInput`` string in bits (may be zero).
   * - pEntrInputCtx
     - Pointer to the Entropy input context.
       The size is equal to the value returned by ``ippsHashDRBG_EntropyInputCtxGetSize``.
   * - pDrbgCtx
     - Pointer to the ``IppsHashDRBGState`` context.
       The size is equal to the value returned by ``ippsHashDRBG_GetSize``.

.. note::

   The minimum length of the entropy input **shall** be equal to or greater than the *security strength*.

Description
-----------

The reseed function:

- Inserts additional entropy by obtaining the entropy input by calling the ``getEntropyInput`` callback function,
  if it's not NULL, or the ``ippsTRNGenRDSEED``, if the CPU supports the RDSEED instruction, or the ``ippsPRNGenRDRAND``,
  if the CPU doesn't support the RDSEED, but supports the RDRAND instruction, and checks whether the entropy is
  sufficient to support the security strength of the DRBG.

- Using the reseed algorithm, combines the current seed from the state with the new entropy input and
  any additional input and update the state.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors. Any other value indicates an error.
   * - ippStsNullPtrErr
     - ``pDrbgCtx`` or ``pEntrInputCtx`` is a NULL pointer.
       The pointer to the buffer that contains the entropy input is NULL.
   * - ippStsContextMatchErr
     - If the Hash DRBG identifier doesn't match.
       If the Entropy input context identifier doesn't match.
   * - ippStsOutOfRangeErr
     - The length of the ``addlInput`` exceeds the maximum possible value.
       The length for the entropy input, passed to the getEntropyInput callback function, is less than the *security strength*
       or exceeds the maximum number of bits that can fit in the entropyInput buffer.
   * - ippStsBadArgErr
     - Prediction resistance is requested but ``predictionResistanceFlag`` has been set to 0.
       The ``addlInput`` is NULL with non-zero ``addlInputBitsLen``, or the ``addlInput`` is not NULL, but ``addlInputBitsLen`` is 0.
   * - ippStsNotSupportedModeErr
     - The CPU does not support the ``RDSEED`` and/or ``RDRAND`` instructions.
   * - ippStsHashOperationErr
     - An error status code was returned during hashing operations.
