.. _hashupdate:



HashUpdate
==========


Digests the current input message stream of the specified length.


Syntax
------


IppStatus ippsHashUpdate(const Ipp8u \*pSrc, int len, IppsHashState
\*pCtx);


IppStatus ippsHashUpdate_rmf(const Ipp8u \*pSrc, int len,
ippsHashState_rmf \*pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table::
   :header-rows: 0

   * -     pSrc
     -  Pointer to the buffer containing a part of or the whole message.
   * -     len
     -  Length of the actual part of the message in bytes.
   * -     pCtx
     -  Pointer to the IppsHashState or IppsHashState_rmf context.




Description
-----------

.. note::


   ippsHashUpdate function is deprecated. Please refer to :ref:`Deprecated Functions <appendix-b-deprecated-functions>`
   section for the recommendations for transition.

The function digests the current input message stream of the specified
length.


The function first integrates the previous partial block with the input
message stream and then partitions them into multiple message blocks (as
specified by the applied hash algorithm) with a possible additional
partial block. For each message block, the function uses the selected
hash algorithm to transform the block into a new chaining digest value.


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
     -     Indicates an error condition in any of the following cases:

           * The length of the input data stream is less than zero.
           * The length of the totally processed stream (including the current update request) exceeds the limit defined by the particular hash algorithm.



