.. _hmac_duplicate:



HMAC_Duplicate
==============


Copies one IppsHMACState or IppsHMACState_rmf context to another.


Syntax
------


IppStatus ippsHMAC_Duplicate(const IppsHMACState\* pSrcCtx,
IppsHMACState\* pDstCtx);


IppStatus ippsHMACDuplicate_rmf(const IppsHMACState_rmf\* pSrcCtx,
IppsHMACState_rmf\* pDstCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrcCtx   
     -  Pointer to the input IppsHMACState or IppsHMACState_rmf context to be cloned.
   * -     pDstCtx   
     -  Pointer to the output IppsHMACState or IppsHMACState_rmf context.




Description
-----------


The function copies one IppsHMACState or IppsHMACState_rmf context to
another.


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
   * -     ippStsContextMatchErr   
     -     Indicates an error condition if any of the context parameters does not match the operation.   



