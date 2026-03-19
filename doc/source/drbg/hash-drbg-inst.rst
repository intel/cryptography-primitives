.. _hash-drbg-inst:

ippsHashDRBG_Instantiate
=========================

Instantiates the Hash DRBG.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_Instantiate(const int requestedInstSecurityStrength,
                                       const int predictionResistanceFlag,
                                       const Ipp8u* persStr,
                                       const int persStrBitsLen,
                                       IppsHashDRBG_EntropyInputCtx* pEntrInputCtx,
                                       IppsHashDRBGState* pDrbgCtx);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - requestedInstSecurityStrength
     - A requested security strength for the instantiation.
   * - predictionResistanceFlag
     - Indicates whether or not prediction resistance may be required
       during requests for pseudorandom bits.
   * - persStr
     - Pointer to the array providing additional bytes for producing a seed (optional but recommended).
   * - persStrBitsLen
     - Length of the ``persStr`` array in bits (may be zero).
   * - pEntrInputCtx
     - Pointer to the Entropy input context.
       The size is equal to the value returned by ``ippsHashDRBG_EntropyInputCtxGetSize``.
   * - pDrbgCtx
     - Pointer to the ``IppsHashDRBGState`` context.
       The size is equal to the value returned by ``ippsHashDRBG_GetSize``.

.. note::

   - Based on the value of ``requestedInstSecurityStrength``, the security strength of the Hash DRBG
     can be changed and set to the value greater than or equal to ``requestedInstSecurityStrength``
     from the set {**128**, **192**, **256**}.
   - The entropy input used in the ``ippsHashDRBG_Instantiate`` **shall** consist of
     entropy and a nonce, with a total length equal to or greater than the sum of
     the *security strength* and one-half the *security strength*.

Description
-----------

The instantiate function:

- Obtains entropy input (including nonce) using the following priority order:

   1. Custom callback: calls ``getEntropyInput()`` if not NULL.
   2. Hardware RDSEED: calls ``ippsTRNGenRDSEED()`` if CPU supports RDSEED instruction.
   3. Hardware RDRAND: calls ``ippsPRNGenRDRAND()`` if CPU supports RDRAND instruction.

  Checks whether the entropy is sufficient to support the security strength.

- Combines entropy input with a personalization string, produces a seed and updates the state.

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
     - The length of the ``persStr`` exceeds maximum possible value.
       The length for the entropy input, passed to the getEntropyInput callback function, is less than the *security strength + ½ security strength*
       or exceeds the maximum number of bits that can fit in the entropyInput buffer.
   * - ippStsBadArgErr
     - The ``requestedInstSecurityStrength`` is more than set security strength.
       The ``persStr`` is NULL with non-zero ``persStrBitsLen``, or the ``persStr`` is not NULL, but ``persStrBitsLen`` is 0.
   * - ippStsNotSupportedModeErr
     - The CPU supports neither ``RDSEED`` nor ``RDRAND`` instructions.
   * - ippStsHashOperationErr
     - An error status code was returned during hashing operations.
