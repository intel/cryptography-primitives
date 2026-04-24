.. _hmac_gettag:


HMAC_GetTag
===========


Computes the current HMAC value of the processed part of the message.


Syntax
------


IppStatus ippsHMAC_GetTag(Ipp8u\* pMD, int mdLen, const IppsHMACState\*
pCtx);


IppStatus ippsHMACGetTag_rmf(Ipp8u\* pMD, int mdLen, const
IppsHMACState_rmf\* pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pMD
     -  Pointer to the authentication tag.
   * -     mdLen
     -  The length of the tag (in bytes).
   * -     pCtx
     -  Pointer to the IppsHMACState or IppsHMACState_rmf context.




Description
-----------


The function computes the message digest based on the current context as
specified in :term:`FIPS PUB 198-1 <[FIPS PUB 198-1]>`. A call
to this function retains the possibility to update the digest.


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
     -     Indicates an error condition if mdLen <1 or mdLen exceeds the maximal length of a particular digest.
   * -     ippStsContextMatchErr
     -     Indicates an error condition if the context parameter does not match the operation.



