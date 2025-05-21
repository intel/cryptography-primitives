.. _one-way-hash-primitives:


One-Way Hash Primitives
=======================


Hash functions are used in cryptography with digital signatures and for
ensuring data integrity.


When used with digital signatures, a publicly available hash function
hashes the message and signs the resulting hash value. The party who
receives the message can then hash the message and check if the block
size is authentic for the given hash value.


Hash functions are also referred to as “message digests” and “one-way
encryption functions”. Both terms are appropriate since hash algorithms
do not have a key like symmetric and asymmetric algorithms and you can
recover neither the length nor the contents of the plaintext message
from the ciphertext.


To ensure data integrity, hash functions are used to compute the hash
value that corresponds to a particular input. Then, if necessary, you
can check if the input data has remained unmodified; you can re-compute
the hash value again using the available input and compare it to the
original hash value.


The :ref:`Hash Functions <hash-functions>`
section describes functions that implement the following hash algorithms
for streaming messages: MD5 :term:`RFC 1321 <[RFC 1321]>`,
SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 :term:`FIPS PUB 180-2 <[FIPS PUB 180-2]>`,
SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 :term:`FIPS PUB 202 <[FIPS PUB 202]>`,
and SM3 :term:`SM3 <[SM3]>`.
These algorithms are widely used in enterprise applications nowadays.


Subsequent sections describe :ref:`Hash Functions for Non-Streaming
Messages <hash-functions-for-non-streaming-messages>`, which
apply hash algorithms to entire (non-streaming) messages, and :ref:`Mask
Generation Functions <mask-generation-functions>`, whose
algorithms are often based on hash computations.


Additionally, Intel® Cryptography Primitives Library
supports two relatively new variants of SHA-512, the so
called SHA-512/224 and SHA-512/256 algorithms. Both employ much of the
basic SHA-512 algorithm but have some specifics. Intel® Cryptography Primitives Library
does not provide a separate API exactly targeting SHA-512/224 and
SHA-512/256. To enable SHA-512/224 and SHA-512/256, Intel® Cryptography Primitives Library
declares extensions of the Hash Functions,
:ref:`Hash Functions for Non-Streaming Messages <hash-functions-for-non-streaming-messages>`,
:ref:`Mask Generation Functions <mask-generation-functions>`, and
:ref:`Keyed Hash Functions <keyed-hash-functions>`. These
extensions use the IppHashAlgId enumerator associated with a particular
hash algorithm as shown in the table below.


.. list-table:: Supported Hash Algorithms
   :header-rows: 1

   * -     Value of IppHashAlgId
     -      Associated Hash Algorithm
   * -      ippHashAlg_SHA1
     -     SHA-1
   * -      ippHashAlg_SHA224
     -     SHA-224
   * -      ippHashAlg_SHA256
     -     SHA-256
   * -      ippHashAlg_SHA384
     -     SHA-384
   * -      ippHashAlg_SHA512
     -     SHA-512
   * -      ippHashAlg_SHA512_224
     -     SHA-512/224
   * -      ippHashAlg_SHA512_256
     -     SHA-512/256
   * -      ippHashAlg_MD5
     -     MD5
   * -      ippHashAlg_SM3
     -     SM3
   * -     ippHashAlg_SHA3_224*
     -     SHA3-224
   * -     ippHashAlg_SHA3_256*
     -     SHA3-256
   * -     ippHashAlg_SHA3_384*
     -     SHA3-384
   * -     ippHashAlg_SHA3_512*
     -     SHA3-512
   * -     ippHashAlg_SHAKE128*
     -     SHAKE128
   * -     ippHashAlg_SHAKE256*
     -     SHAKE256



`* - supported by reduced memory footprint functions only. The support of the SHA3 family 
algorithm was added only for reduced memory footprint(_rmf) functions, the functionality 
of the deprecated API was not extended.`


Reduced Memory Footprint Functions
----------------------------------


When your application uses the IppHashAlgId enumerator, it gets linked
to all available hashing algorithm implementations. This results in
unnecessary memory overhead if the application does not need all the
algorithms. Intel® Cryptography Primitives Library includes a number of *reduced memory
footprint* functions that allow you to select the exact hashing methods
for your application's needs. These functions have the ``_rmf`` suffix
in their names and use pointers to IppsHashMethod structure variables
instead of IppHashAlgId values. To get a pointer to a IppsHashMethod
structure variable, call an appropriate function from the table below.
See :ref:`HashMethod <hashmethod>` for
the syntax.


.. note::


   Functions that have the ``_TT`` suffix in their names return pointers
   to dynamically dispatched IppsHashMethod structures. These structures
   check for support of the Intel® Secure Hash Algorithm - New Instructions (Intel® SHA-NI)
   instruction set at run time and choose the implementation of an algorithm
   depending on the outcome of the check. Using such IppsHashMethod structures leads
   to a slightly larger memory footprint compared to applications that use
   non-dynamically dispatched IppsHashMethod structures.


.. list-table:: ``HashMethod`` Functions
   :header-rows: 1

   * -     Function name
     -      Returns pointer to implementation of
   * -      ippsHashMethod_SHA1
     -      SHA1 (without the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHA1_NI
     -      SHA1 (using the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHA1_TT
     -      SHA1 (using the Intel® SHA-NI instructions set if it is available at run time)
   * -      ippsHashMethod_SHA256
     -      SHA256 (without the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHA256_NI
     -      SHA256 (using the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHA256_TT
     -      SHA256 (using the Intel® SHA-NI instructions set if it is available at run time)
   * -      ippsHashMethod_SHA224
     -      SHA224 (without the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHA224_NI
     -      SHA224 (using the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHA224_TT
     -      SHA224 (using the Intel® SHA-NI instructions set if it is available at run time)
   * -      ippsHashMethod_SHA384
     -      SHA384 (without the Intel® SHA512 instruction set)
   * -      ippsHashMethod_SHA384_NI
     -      SHA384 (using the Intel® SHA512 instruction set)
   * -      ippsHashMethod_SHA384_TT
     -      SHA384 (using the Intel® SHA512 instructions set if it is available at run time)
   * -      ippsHashMethod_SHA512
     -      SHA512 (without the Intel® SHA512 instruction set)
   * -      ippsHashMethod_SHA512_NI
     -      SHA512 (using the Intel® SHA512 instruction set)
   * -      ippsHashMethod_SHA512_TT
     -      SHA512 (using the Intel® SHA512 instructions set if it is available at run time)
   * -      ippsHashMethod_SHA512_256
     -      SHA512-256 (without the Intel® SHA512 instruction set)
   * -      ippsHashMethod_SHA512_256_NI
     -      SHA512-256 (using the Intel® SHA512 instruction set)
   * -      ippsHashMethod_SHA512_256_TT
     -      SHA512-256 (using the Intel® SHA512 instructions set if it is available at run time)
   * -      ippsHashMethod_SHA512_224
     -      SHA512-224 (without the Intel® SHA512 instruction set)
   * -      ippsHashMethod_SHA512_224_NI
     -      SHA512-224 (using the Intel® SHA512 instruction set)
   * -      ippsHashMethod_SHA512_224_TT
     -      SHA512-224 (using the Intel® SHA512 instructions set if it is available at run time)
   * -      ippsHashMethod_MD5
     -      MD5
   * -      ippsHashMethod_SM3
     -      SM3 (without the Intel® SM3 instruction set)
   * -      ippsHashMethod_SM3_NI
     -      SM3 (using the SM3 instruction set)
   * -      ippsHashMethod_SM3_TT
     -      SM3 (using the Intel® SM3 instruction set if it is available at run time)
   * -      ippsHashMethod_SHA3_224
     -      SHA3_224 (without the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHA3_256
     -      SHA3_256 (without the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHA3_384
     -      SHA3_384 (without the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHA3_512
     -      SHA3_512 (without the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHAKE128
     -      SHAKE128 (without the Intel® SHA-NI instruction set)
   * -      ippsHashMethod_SHAKE256
     -      SHAKE256 (without the Intel® SHA-NI instruction set)




.. note::


   .. rubric:: Important
      :class: NoteTipHead

   The crypto community does not consider SHA-1 or MD5 algorithms secure
   anymore.


   Recommendation: use a more secure hash algorithm (for example, any
   algorithm from the SHA-2 family) instead of SHA-1 or MD5.

.. toctree::
   :maxdepth: 1


   hash-functions
   hash-functions-for-non-streaming-messages
   mask-generation-functions
