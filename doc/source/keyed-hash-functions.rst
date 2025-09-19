.. _keyed-hash-functions:


Keyed Hash Functions
====================


The Intel® Cryptography Primitives Library HMAC primitive functions, described in this section, use
various HMAC schemes based on one-way hash functions described in
:ref:`One-Way Hash Primitives <one-way-hash-primitives>`.


Usage model of the generalized HMAC functions is similar to the model
explained below.


Each HMAC scheme is implemented as a set of the primitive functions.
Each primitive implementing HMAC uses the HashState context as an
operational vehicle to carry all necessary variables to manage
computation of the chaining digest value.


The following example illustrates how the application code can apply the
implemented HMAC-SHA1 hash standard to digest the input message stream:


#. Call the function
   :ref:`HMAC_GetSize <hmac_getsize>` to
   get the size required to configure the HashState context.


#. Ensure that the required memory space is properly allocated. With the
   allocated memory, call the function
   :ref:`HMAC_Init <hmac_init>` with
   the value of hashAlg equal to ippHashAlg_SHA1 to set up key material
   and the initial context state with the SHA-1 specified initialization
   vectors.


#. Keep calling the function
   :ref:`HMAC_Update <hmac_update>` to
   digest incoming message stream in the queue till its completion. To
   determine the current value of the message digest, call
   :ref:`HMAC_GetTag <hmac_gettag>`
   between the two calls to HMACUpdate.


#. Call the function
   :ref:`HMAC_Final <hmac_final>` to
   pad the partial block into a final SHA-1 message block and transform
   it into a resulting HMAC value.


#. Clean up secret data stored in the context.


#. Call the operating system memory free service function to release the
   HashState context.


The HashState context is position-dependent. The :ref:`HMACPack,
HMACUnpack <hmac_pack-hmac_unpack>`
functions transform it to a position-independent form and vice versa:


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   The crypto community does not consider HMACSHA1 or HMACMD5 secure
   anymore.


   Recommendation: use a more secure hash algorithm (for example, any
   algorithm from the SHA-2 family) instead of HMACSHA1 or HMACMD5.



.. rubric:: Related Information

:ref:`data-security-considerations`


.. toctree::
   :maxdepth: 1


   hmac_getsize
   hmac_init
   hmac_pack-hmac_unpack
   hmac_duplicate
   hmac_update
   hmac_final
   hmac_gettag
   hmac_message
   hkdf
   hkdf_extract
   hkdf_expand
