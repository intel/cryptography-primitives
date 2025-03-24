.. _hashmethodset:


HashMethodSet
=============


Initializes IppsHashMethod structure by pre-defined hash algorithm
parameters.


Syntax
------


const IppStatus ippsHashMethodSet_SHA1(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA1_NI(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA1_TT(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA256(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA256_NI(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA256_TT(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA224(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA224_NI(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA224_TT(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA512(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA512_NI(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA512_TT(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA384(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA384_NI(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA384_TT(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA512_224(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA512_224_NI(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA512_224_TT(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA512_256(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA512_256_NI(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SHA512_256_TT(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_MD5(IppsHashMethod\* pMethod);


const IppStatus ippsHashMethodSet_SM3(IppsHashMethod\* pMethod);

const IppStatus ippsHashMethodSet_SM3_NI(IppsHashMethod\* pMethod);

const IppStatus ippsHashMethodSet_SM3_TT(IppsHashMethod\* pMethod);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -      IppsHashMethod\*
     -  Pointer to the uninitialized hash method.




Description
-----------


.. note::


   The ippsHashMethodSet_MD5 function is deprecated. The MD5 algorithm
   is considered weak due to known attacks on it. The functionality
   remains in the library, but the implementation will no longer be
   optimized and no security patches will be applied.


Each of these functions accepts a pointer to uninitialized memory of the
size obtained using
:ref:`HashMethodGetSize <hashmethodgetsize>`,
and initializes this memory tomethod-definedimplementation of a
particular hash algorithm. Use these functionsin calls to
:ref:`HashInit <hashinit>` and
:ref:`HashMessage <hashmessage>`.


Return Values
-------------


.. list-table::
   :header-rows: 0

   * -      ippStsNoErr
     -  Indicates no errors. Any other value indicates an error or warning.
   * -      ippStsNullPtrErr
     -  Indicates an error condition if any of the specified pointers is NULL.



