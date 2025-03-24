.. _hmac_update:


HMAC_Update
===========


Digests the current input message stream of the specified length.


Syntax
------


IppStatus ippsHMAC_Update(const Ipp8u \*pSrc, int len, IppsHMACState
\*pCtx);


IppStatus ippsHMACUpdate_rmf(const Ipp8u \*pSrc, int len,
IppsHMACState_rmf \*pCtx);


Include Files
-------------


``ippcp.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pSrc    
     -  Pointer to the buffer containing a part of the whole message.
   * -     len   
     -  The length of the actual part of the message in bytes.
   * -     pCtx   
     -  Pointer to the IppsHMACState or IppsHMACState_rmf context.




Description
-----------


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
     -     Indicates an error condition if the length of the input data stream is less than zero.   



