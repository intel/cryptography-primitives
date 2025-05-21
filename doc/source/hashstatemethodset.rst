.. _hashstatemethodset:

HashStateMethodSet
==================

Updates the ``IppsHashState_rmf`` structure with a new pointer to ``IppsHashMethod`` and initializes it with the pre-defined hash algorithm parameters.

Syntax
------

IppStatus ippsHashStateMethodSet_SM3(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SM3_NI(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SM3_TT(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA256(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA256_NI(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA256_TT(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA224(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA224_NI(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA224_TT(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA512(IppsHashState_rmf* pState, IppsHashMethod* pMethod) 

IppStatus ippsHashStateMethodSet_SHA512_NI(IppsHashState_rmf* pState, IppsHashMethod* pMethod) 

IppStatus ippsHashStateMethodSet_SHA512_TT(IppsHashState_rmf* pState, IppsHashMethod* pMethod) 

IppStatus ippsHashStateMethodSet_SHA384(IppsHashState_rmf* pState, IppsHashMethod* pMethod) 

IppStatus ippsHashStateMethodSet_SHA384_NI(IppsHashState_rmf* pState, IppsHashMethod* pMethod) 

IppStatus ippsHashStateMethodSet_SHA384_TT(IppsHashState_rmf* pState, IppsHashMethod* pMethod) 

IppStatus ippsHashStateMethodSet_SHA512_256(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA512_256_NI(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA512_256_TT(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA512_224(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA512_224_NI(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA512_224_TT(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA3_224(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA3_256(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA3_384(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHA3_512(IppsHashState_rmf* pState, IppsHashMethod* pMethod)

IppStatus ippsHashStateMethodSet_SHAKE128(IppsHashState_rmf* pState, IppsHashMethod* pMethod, int digestBitsize)

IppStatus ippsHashStateMethodSet_SHAKE256(IppsHashState_rmf* pState, IppsHashMethod* pMethod, int digestBitsize)

Include Files
-------------

``ippcp.h``


Parameters
----------

.. list-table:: 
   :header-rows: 0

   * - pState
     - Pointer to the ``IppsHashState_rmf`` context being updated. 
   * - pMethod
     - Pointer to the method for the update of the context.
   * - digestBitsize
     - The size of output digest in bits. Should be positive multiple of 8 integer.
		 
	  
Description
-----------

Each of these functions:

* Accepts pointer to ``IppsHashState_rmf`` context, which is proceeded with ``ippsHashInit`` function before.
* Updates stored inside of the context pointer to ``IppsHashMethod``. 
* Initializes it to the method-defined implementation of a particular hash algorithm. 

Use these functions in calls to ``HashInit`` and ``HashMessage``.


Return Values
-------------

.. list-table:: 
   :header-rows: 0

   * - ippStsNoErr
     - Indicates no errors. Any other value indicates an error or warning.
   * - ippStsNullPtrErr
     - Indicates an error condition if any of the specified pointers are NULL.
   * - ippStsOutOfRangeErr     
     - Indicates an error condition if digestBitsize is not positive multiple of 8 integer.
 

