.. _hmac_final:

HMAC_Final
==========


Completes computation of the HMAC value.


Syntax
------


IppStatus ippsHMAC_Final(Ipp8u \*pMD, int mdLen, IppsHMACState \*pCtx);


IppStatus ippsHMACFinal_rmf(Ipp8u \*pMD, int mdLen, IppsHMACState_rmf
\*pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pMD    
     -  Pointer to the resultant HMAC value.
   * -     mdLen   
     -  Specified HMAC length.
   * -     pCtx   
     -  Pointer to the IppsHMACState or IppsHMACState_rmf context.




Description
-----------


The function completes calculation of the digest value and stores the
result at the memory location specified by pMD.


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
     -     Indicates an error condition if the context parameter does not match the operation.   
   * -     ippStsLengthErr   
     -     Indicates an error condition if mdLen is less than one or greater than the length of the hash value.   



