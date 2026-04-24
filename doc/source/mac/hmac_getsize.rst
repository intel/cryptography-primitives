.. _hmac_getsize:



HMAC_GetSize
============


Gets the size of the IppsHMACState or IppsHMACState_rmf context.


Syntax
------


IppStatus ippsHMAC_GetSize(int \*pSize);


IppStatus ippsHMACGetSize_rmf(int \*pSize);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pSize
     -  Pointer to the value of the IppsHMACState or IppsHMACState_rmf context size.




Description
-----------

.. note::


   ippsHMAC_GetSize function is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The function gets the size of the IppsHMACState or IppsHMACState_rmf
context in bytes and stores it in pSize.


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



