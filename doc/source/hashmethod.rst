.. _hashmethod:


HashMethod
==========


Returns a pointer to a pre-defined hash algorithm.


Syntax
------


const IppsHashMethod\* ippsHashMethod_SHA1(void);


const IppsHashMethod\* ippsHashMethod_SHA1_NI(void);


const IppsHashMethod\* ippsHashMethod_SHA1_TT(void);


const IppsHashMethod\* ippsHashMethod_SHA256(void);


const IppsHashMethod\* ippsHashMethod_SHA256_NI(void);


const IppsHashMethod\* ippsHashMethod_SHA256_TT(void);


const IppsHashMethod\* ippsHashMethod_SHA224(void);


const IppsHashMethod\* ippsHashMethod_SHA224_NI(void);


const IppsHashMethod\* ippsHashMethod_SHA224_TT(void);


const IppsHashMethod\* ippsHashMethod_SHA512(void);


const IppsHashMethod\* ippsHashMethod_SHA512_NI(void);


const IppsHashMethod\* ippsHashMethod_SHA512_TT(void);


const IppsHashMethod\* ippsHashMethod_SHA384(void);


const IppsHashMethod\* ippsHashMethod_SHA384_NI(void);


const IppsHashMethod\* ippsHashMethod_SHA384_TT(void);


const IppsHashMethod\* ippsHashMethod_SHA512_224(void);


const IppsHashMethod\* ippsHashMethod_SHA512_224_NI(void);


const IppsHashMethod\* ippsHashMethod_SHA512_224_TT(void);


const IppsHashMethod\* ippsHashMethod_SHA512_256(void);


const IppsHashMethod\* ippsHashMethod_SHA512_256_NI(void);


const IppsHashMethod\* ippsHashMethod_SHA512_256_TT(void);


const IppsHashMethod\* ippsHashMethod_MD5(void);


const IppsHashMethod\* ippsHashMethod_SM3(void);

const IppsHashMethod\* ippsHashMethod_SM3_NI(void);

const IppsHashMethod\* ippsHashMethod_SM3_TT(void);


const IppsHashMethod\* ippsHashMethod_SHA3_224(void);

const IppsHashMethod\* ippsHashMethod_SHA3_256(void);

const IppsHashMethod\* ippsHashMethod_SHA3_384(void);

const IppsHashMethod\* ippsHashMethod_SHA3_512(void);


const IppsHashMethod\* ippsHashMethod_SHAKE128(int digestBitsize);

const IppsHashMethod\* ippsHashMethod_SHAKE256(int digestBitsize);

Include Files
-------------


``ippcp.h``



Parameters
----------


.. list-table::
   :header-rows: 0

   * -      digestBitsize
     -  The size of output digest in bits. Should be positive multiple of 8 integer.




Description
-----------


.. note::


   The ippsHashMethod_MD5 function is deprecated. The MD5 algorithm is
   considered weak due to known attacks on it. The functionality remains
   in the library, but the implementation will no longer be optimized
   and no security patches will be applied.


Each of these functions returns a pointer to a method-defined
implementation of a particular hash algorithm. Use these functions in
calls to :ref:`HashInit <hashinit>`
and :ref:`HashMessage <hashmessage>`.
See table :ref:`HashMethod Functions <one-way-hash-primitives>`
for an explanation of the values returned by the HashMethod functions.


.. note::


   This function is not thread-safe due to internal structure reinitialization. 
   For optimal performance and thread safety, cache the returned pointer to a separate 
   variable and reuse it across calls. Alternatively, manual heap allocation for 
   method storage offers similar performance but requires careful memory management.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -     const ippsHashMethod\*
     -  Pointer to the particular hash method.
   * -     ``NULL``
     -  digestBitsize is not positive multiple of 8 integer.



