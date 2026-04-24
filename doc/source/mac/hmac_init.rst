.. _hmac_init:

HMAC_Init
=========


Initializes user-supplied memory as IppsHMACState or IppsHMACState_rmf
context for future use.


Syntax
------


IppStatus ippsHMAC_Init(const Ipp8u \*pKey, int keyLen, IppsHMACState
\*pCtx, IppHashAlgId hashAlg);


IppStatus ippsHMACInit_rmf(const Ipp8u\* pKey, int keyLen,
IppsHMACState_rmf\* pCtx, const IppsHashMethod\* pMethod);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pKey    
     -  Pointer to the user-supplied key.
   * -     keyLen   
     -  Key length in bytes.
   * -     pCtx   
     -  Pointer to the IppsHMACState or IppsHMACState_rmf context being initialized.
   * -     hashAlg   
     -  Identifier of the hash algorithm.
   * -     pMethod   
     -  Pointer to the hash method.




Description
-----------


The function initializes the memory pointed to by pCtx as the
IppsHMACState or IppsHMACState_rmf context. The function also sets up
the initial chaining digest value according to the hash algorithm
specified by the hashAlg or pMethodparameter and computes necessary key
material from the supplied key pKey. The hashAlg parameter can take one
of the values listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.
To get a value for the pMethod parameter, call one of the
:ref:`HashMethod <hashmethod>`
functions.


.. note::


   This function has a *reduced memory footprint* version. To learn
   more, see :ref:`Reduced Memory Footprint Functions <one-way-hash-primitives>`.


Return Values
-------------


.. list-table:: 
   :header-rows: 0

   * -     ippStsNoErr   
     -     Indicates no error. Any other value indicates an error or warning.   
   * -     ippStsNullPtrErr   
     -     Indicates an error condition if any of the specified pointers is NULL.   
   * -     ippStsLengthErr   
     -     Indicates an error condition if keyLen is less than one.   
   * -     ippStsNotSupportedModeErr   
     -     Indicates an error condition if the hashAlg parameter does not match any value of IppHashAlg listed in table :ref:`Supported Hash Algorithms <one-way-hash-primitives>`.   



.. rubric:: Related Information

:ref:`data-security-considerations`

