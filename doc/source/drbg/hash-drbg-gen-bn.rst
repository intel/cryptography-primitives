.. _hash-drbg-gen-bn:

ippsHashDRBG_GenBN
===================

Generates a pseudorandom positive Big Number of the specified bit length.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_GenBN(IppsBigNumState* pRand,
                                 int nBits,
                                 const int requestedSecurityStrength,
                                 const int predictionResistanceRequest,
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

   * - pRand
     - Pointer to the output pseudorandom Big Number.
   * - nBits
     - Requested number of bits to be generated.
   * - requestedSecurityStrength
     - The security strength to be associated with the requested pseudorandom bits.
   * - predictionResistanceRequest
     - Indicates whether or not prediction resistance is to be provided during the request
       (whether or not fresh entropy bits are required).
   * - addlInput
     - Pointer to the array containing additional input (optional).
   * - addlInputBitsLen
     - Length of the ``addlInput`` in bits (may be zero).
   * - pEntrInputCtx
     - Pointer to the Entropy input context.
       The size is equal to the value returned by ``ippsHashDRBG_EntropyInputCtxGetSize``.
   * - pDrbgCtx
     - Pointer to the ``IppsHashDRBGState`` context.
       Size equals to the value returned by ``ippsHashDRBG_GetSize``.

Description
-----------

The ``ippsHashDRBG_GenBN`` function:

- Calls the reseed function to incorporate fresh entropy when prediction resistance is requested or
  the Hash DRBG has reached the end of its reseed interval.

- Generates a pseudorandom Big Number of the specified ``nBits`` length and updates the working state.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       Any other value indicates an error.
   * - ippStsNullPtrErr
     - ``pRand``, ``pDrbgCtx`` or ``pEntrInputCtx`` is a NULL pointer.
   * - ippStsContextMatchErr
     - If the Big Number identifier doesn't match.
       If the Hash DRBG identifier doesn't match.
       If the Entropy input context identifier doesn't match.
   * - ippStsBadArgErr
     - Prediction resistance is requested but ``predictionResistanceFlag`` has been set to 0 during the initialization of `pDrbgCtx` state.
       The ``nBits`` exceeds the maximum possible number of bits per request or the maximum possible value.
       The ``addlInput`` is NULL with non-zero ``addlInputBitsLen``, or the ``addlInput`` is not NULL, but ``addlInputBitsLen`` is 0.
   * - ippStsOutOfRangeErr
     - The length of ``addlInput`` exceeds the maximum possible value.
       The length for the entropy input, passed to the getEntropyInput callback function, is less than the *security strength*
       or exceeds the length of the entropy input buffer.
   * - ippStsNotSupportedModeErr
     - The CPU does not support the ``RDSEED`` and/or ``RDRAND`` instructions.
   * - ippStsHashOperationErr
     - An error status code was returned during hashing operations.
