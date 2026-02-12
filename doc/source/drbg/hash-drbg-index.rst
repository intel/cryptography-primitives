.. _hash-drbg-index:

Hash DRBG
=========

**Deterministic Random Bit Generator (DRBG)** is the class of random bit generators (RBGs)
for computing bits deterministically using an algorithm.
A DRBG is based on a DRBG mechanism and includes a source of randomness.
A DRBG mechanism uses an algorithm (i.e., a DRBG algorithm) that produces a sequence of bits
from an initial value that is determined by a seed that is determined from the output of the
randomness source. Once the seed is provided and the initial value is determined, the DRBG
is said to be instantiated and may be used to produce output. The seed used to instantiate
the DRBG must contain sufficient entropy to provide an assurance of randomness.

The implementation is based on the `NIST SP 800-90A Rev. 1 <https://csrc.nist.gov/pubs/sp/800/90/a/r1/final>`__

The DRBG mechanism requires five functions: instantiate, generate, reseed, uninstantiate and health testing.

A **Hash DRBG** mechanism is based on a hash function that is one-way and may be used by consuming applications
requiring various security strengths, providing that the appropriate hash function is used and
sufficient entropy is obtained for the seed.
The **Hash DRBG** requires the use of a hash function during the instantiate, reseed and generate functions.

Security Strength
------------------

The security strength is determined by the user-specified hashing method and can take one of
the values from the set {**128**, **192**, **256**}.
The hashing methods and their corresponding maximum security strengths are shown in Table 1.

.. _hash-drbg-max-sec-strength-for-hash-funcs:

**Table 1: Maximum security strengths for hash functions in bits**

+-------------------+----------------------------------------+
| Security strength | Hashing method                         |
+===================+========================================+
|        128        | SHA-1                                  |
+-------------------+----------------------------------------+
|        192        | SHA-224, SHA-512/224                   |
+-------------------+----------------------------------------+
|        256        | SHA-256, SHA-512/256, SHA-384, SHA-512 |
+-------------------+----------------------------------------+

Since the current implementation supports only SHA-256, SHA-512/256, SHA-384, and SHA-512 hashing
methods, the security strength is initially set to 256 bits. However, it can be changed when a different
security strength is requested during instantiation (see :ref:`The Instantiate function description <hash-drbg-inst>`).

Refer to the `NIST SP 800-57 Part 1 Rev. 5 <https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final>`__
for more details.

.. _hash-drbg-min-and-max-values:

Minimum and maximum values for the Hash DRBG
------------------------------------------------------

+--------------------------------------------+-----------------------------------+
| Lowest supported security strength         | 128 bits                          |
+--------------------------------------------+-----------------------------------+
| Minimum entropy input length               | *sec.strength* + ½ *sec.strength* |
+--------------------------------------------+-----------------------------------+
| Maximum entropy input length               | 2\ :sup:`31` - 1 bits             |
+--------------------------------------------+-----------------------------------+
| Maximum personalization string length      | 2\ :sup:`31` - 1 bits             |
+--------------------------------------------+-----------------------------------+
| Maximum additional_input length            | 2\ :sup:`31` - 1 bits             |
+--------------------------------------------+-----------------------------------+
| Maximum number of bits per request         | 2\ :sup:`16` bits                 |
+--------------------------------------------+-----------------------------------+
| Maximum number of requests between reseeds | 2\ :sup:`24`                      |
| (reseed interval)                          |                                   |
+--------------------------------------------+-----------------------------------+

Entropy Input
--------------

Within the current implementation of the Hash DRBG, a separate entity ``IppsHashDRBG_EntropyInputCtx``
is used to store entropy input buffer.
The entropy input context contains a pointer to the entropy input buffer and
the maximum length of this buffer in bits.

Prediction Resistance
----------------------

The implementation of the Hash DRBG supports prediction resistance and
provides it upon request.

The supported hashing methods
------------------------------

- SHA-256
- SHA-512/256
- SHA-384
- SHA-512

Example. Random Numbers Generation
-----------------------------------

.. code:: cpp

    #include "ippcp.h"

    ...

    /* Must provide the entropy input during instantiation, reseeding,
       and, if prediction resistance is requested, generation */
    static IppStatus getEntropyInputCallback(Ipp8u* entropyInput,
                                             int* pEntropyBitsLen,
                                             const int minEntropyInBits,
                                             const int maxEntropyInBits,
                                             const int predResistanceRequest)
    {
        /* Implementation of obtaining entropy input from an entropy source,
           an NRBG or another DRBG */

        ...

        return status;
    }

      ...

    {
        const IppsHashMethod* pHashMethod = ippsHashMethod_SHA256_TT();

        int entrInputCtxSize;
        /* As an example, set the entropy input buffer size to the minimum value,
           since requestedSecurityStrength is set to 128 below */
        int entrInputBitsLen = 192;
        /* Get the size (in bytes) for the Entropy input context */
        status = ippsHashDRBG_EntropyInputCtxGetSize(&entrInputCtxSize, entrInputBitsLen, pHashMethod);

        /* Allocate memory for the Entropy input context */
        std::vector<Ipp8u> entrInputCtxBuff(entrInputCtxSize);
        IppsHashDRBG_EntropyInputCtx* pEntrInputCtx = (IppsHashDRBG_EntropyInputCtx*)(entrInputCtxBuff.data());

        /* Initialize the context */
        status = ippsHashDRBG_EntropyInputCtxInit(pEntrInputCtx, entrInputBitsLen, getEntropyInputCallback);

        int requestedSecurityStrength = 128;
        /* Indicates whether or not prediction resistance may be required */
        int predictionResistanceFlag = 1;

        int size;
        /* Get the size (in bytes) for the Hash DRBG state */
        status = ippsHashDRBG_GetSize(&size, pHashMethod);

        /* Allocate memory for the Hash DRBG context */
        std::vector<Ipp8u> ctxBuff(size);
        IppsHashDRBGState* pDrbgCtx = (IppsHashDRBGState*)(ctxBuff.data());

        /* Initialize the state and set hashing method and some initial values */
        status = ippsHashDRBG_Init(pHashMethod, pDrbgCtx);

        /* Instantiate the Hash DRBG */
        status = ippsHashDRBG_Instantiate(requestedSecurityStrength,
                                          predictionResistanceFlag,
                                          persStr.data(),
                                          persStrBitsLen,
                                          pEntrInputCtx,
                                          pDrbgCtx);

        /* Indicates whether or not prediction resistance is to be provided during the request */
        int predResistRequested = 1;
        std::vector<Ipp8u> returnedRndData(returnedBitsLen / 8, 0);

        /* Generate pseudorandom 32-bit numbers.
           If prediction resistance is requested, calls reseed inside and
           requires fresh entropy input */
        status = ippsHashDRBG_Gen((Ipp32u*)returnedRndData.data(),
                                  returnedBitsLen,
                                  requestedSecurityStrength,
                                  predResistRequested,
                                  addtlInputGenerate.data(),
                                  addtlInputGenLen,
                                  pEntrInputCtx,
                                  pDrbgCtx);

        /* Remove the Hash DRBG instantiation */
        status = ippsHashDRBG_Uninstantiate(pDrbgCtx);

        ...

Related functionality:
----------------------

.. toctree::
   :maxdepth: 1

   hash-drbg-entr-input-get-size
   hash-drbg-entr-input-init
   hash-drbg-get-size
   hash-drbg-init
   hash-drbg-inst
   hash-drbg-reseed
   hash-drbg-gen
   hash-drbg-gen-bn
   hash-drbg-uninst
   hash-drbg-inst-test
   hash-drbg-reseed-test
   hash-drbg-gen-test
