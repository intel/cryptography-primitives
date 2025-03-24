.. _hash-functions:



Hash Functions
==============


.. note::


   The MD5 algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: SHA-2. For more information, see
   *Fast Collision Attack on MD5* (https://eprint.iacr.org/2013/170.pdf)
   and *How to Break MD5 and Other Hash Functions*
   (http://merlot.usc.edu/csac-f06/papers/Wang05a.pdf).


Functions described in this section apply hash algorithms to digesting
streaming messages.


Usage model of the generalized hash functions is similar to the model
explained below.


A primitive implementing a hash algorithm uses the state context
IppsHashState as an operational vehicle to carry all necessary variables
to manage the computation of the chaining digest value.


The following example illustrates how the application code can apply the
implemented SHA-1 hash standard to digest the input message stream.


#. Call the function
   :ref:`HashGetSize <hashgetsize>` to
   get the size required to configure the IppsHashState context.


#. Ensure that the required memory space is properly allocated. With the
   allocated memory, call the
   :ref:`HashInit <hashinit>`
   function with the value of hashAlg equal to ippHashAlg_SHA1 to set up
   the initial context state with the SHA-1 specified initialization
   vectors.


#. Keep calling the function
   :ref:`HashUpdate <hashupdate>` to
   digest incoming message stream in the queue till its completion. To
   determine the current value of the digest, call
   :ref:`HashGetTag <hashgettag>`
   between the two calls to HashUpdate.


#. Call the function
   :ref:`HashFinal <hashfinal>` to pad
   the partial block into a final SHA-1 message block and transform it
   into a 160-bit message digest value.


#. Clean up secret data stored in the context.


#. Call the operating system memory free service function to release the
   IppsSHA1StateIppsHashState context.


The IppsHashState context is position-dependent. The :ref:`HashPack,
HashUnpack <hashpack-hashunpack>`
functions transform this context to a position-independent form and vice
versa.


.. note::


   For memory-critical applications, consider using :ref:`Reduced Memory
   Footprint Functions <one-way-hash-primitives>`.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   The crypto community does not consider SHA-1 or MD5 algorithms secure
   anymore.


   Recommendation: use a more secure hash algorithm (for example, any
   algorithm from the SHA-2 family) instead of SHA-1 or MD5.


.. rubric:: Related Information

:ref:`data-security-considerations`

.. toctree::
   :maxdepth: 1


   hashgetsize
   hashinit
   hashpack-hashunpack
   hashduplicate
   hashupdate
   hashfinal
   hashgettag
   hashmethod
   hashmethodset
   hashstatemethodset
   hashmethodgetsize
