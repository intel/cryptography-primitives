.. _hashgetsize:


HashGetSize
===========


Gets the size of the IppsHashState or IppsHashState_rmf context in
bytes.


Syntax
------


IppStatus ippsHashGetSize(int \*pSize);


IppStatus ippsHashGetSize_rmf(int \*pSize);


IppStatus ippsHashGetSizeOptimal_rmf(int \*pSize, IppsHashMethod\* pMethod);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pSize
     -  Pointer to the value of the IppsHashState or IppsHashState_rmf context size.
   * -      IppsHashMethod\*
     -  Pointer to the hash method.




Description
-----------

.. note::


   ippsHashGetSize function is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The functions get the size of the IppsHashState or IppsHashState_rmf
context in bytes and stores it in \*pSize. ippsHashGetSize and ippsHashGetSize_rmf are universal for supported hash methods 
and provide a size sufficient for the largest method. ippsHashGetSizeOptimal_rmf provides the minimum size required 
for a particular method and can be used to reduce memory consumption.


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



