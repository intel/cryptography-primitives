.. _hashduplicate:



HashDuplicate
=============


Copies one IppsHashState or IppsHashState_rmf context to another.


Syntax
------


IppStatus ippsHashDuplicate(const IppsHashState\* pSrcCtx,
IppsHashState\* pDstCtx);


IppStatus ippsHashDuplicate_rmf(const ippsHashState_rmf\* pSrcCtx,
ippsHashState_rmf\* pDstCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pSrcCtx
     -  Pointer to the input IppsHashState or IppsHashState_rmf context to be cloned.
   * -     pDstCtx
     -  Pointer to the output IppsHashState or IppsHashState_rmf context.




Description
-----------

.. note::


   ippsHashDuplicate function is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The function copies one IppsHashState or IppsHashState_rmf context to
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
   * -     ippStsNotSupportedModeErr
     -     Indicates an error condition if the provided hash algorithm identifier is not supported.



