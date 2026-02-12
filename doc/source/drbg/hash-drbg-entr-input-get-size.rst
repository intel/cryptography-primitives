.. _hash-drbg-entr-input-get-size:

ippsHashDRBG_EntropyInputCtxGetSize
====================================

Gets the size (in bytes) for the Entropy input context.

Syntax
------

.. code:: cpp

    IppStatus ippsHashDRBG_EntropyInputCtxGetSize(int* pEntrInputSize,
                                                  const int entrInputBufBitsLen,
                                                  const IppsHashMethod* pHashMethod);

Include Files
-------------

``ippcp.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pEntrInputSize
     - Pointer to the Entropy input context size.
   * - entrInputBufBitsLen
     - The length of the buffer containing the entropy input and the nonce.
       ``entrInputBufBitsLen`` must be at least equal to the minimum entropy input length
       specified in :ref:`Minimum and maximum values for the Hash DRBG <hash-drbg-min-and-max-values>` to accommodate both
       the entropy input and the nonce during instantiation.
   * - pHashMethod
     - Pointer to the hash method (may be NULL).

Description
------------

Gets the size for the ``IppsHashDRBG_EntropyInputCtx``.

The result is stored to ``*pEntrInputSize``.

.. note::

   If the hash method is not specified (NULL pointer is passed), SHA-256 is used by default.

Return Values
-------------

.. list-table::
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no error. All single operations executed without errors.
       Any other value indicates an error.
   * - ippStsNullPtrErr
     - ``pEntrInputSize`` is a NULL pointer.
   * - ippStsOutOfRangeErr
     - ``entrInputBufBitsLen < 1``.
   * - ippStsNotSupportedModeErr
     - The hash algorithm is not supported.
   * - ippStsLengthErr
     - The length of the Entropy input buffer is less than the minimum entropy input length (see :ref:`Minimum and maximum values for the Hash DRBG <hash-drbg-min-and-max-values>`).
