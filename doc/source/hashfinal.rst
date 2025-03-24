.. _hashfinal:



HashFinal
=========


Completes computation of the digest value.


Syntax
------


IppStatus ippsHashFinal(Ipp8u \*pMD, IppsHashState \*pCtx);


IppStatus ippsHashFinal_rmf(Ipp8u \*pHash, ippsHashState_rmf \*pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pMD, pHash
     -  Pointer to the resultant digest value.
   * -     pCtx
     -  Pointer to the IppsHashState or IppsHashState_rmf context.




Description
-----------

.. note::


   ippsHashFinal function is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The function completes calculation of the digest value and stores the
result at the specified memory location, then re-initializes the pCtx
context.


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



