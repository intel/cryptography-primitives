.. _mbx_sm3_update_mb16:



mbx_sm3_update_mb16
===================


Digests the current streams of input messages with the specified length.


Syntax
------


mbx_status16 mbx_sm3_update_mb16( const int8u \*pa_msg[16], intlen[16],
SM3_CTX_mb16\*p_state);


Include Files
-------------


``crypto_mb/sm3.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_msg   
     -  Array of pointers to the buffers containing parts of the whole messages.
   * -     len   
     -  Array of lengths of the actual parts of the messages in bytes.
   * -     p_state   
     -  Pointer to the SM3_CTX_mb16 context.




Description
-----------


The function digests the current streams of input messages passed by
pa_msg parameter. The specified messages lengths are passed through len
array. You can call the function several times with the same p_state to
produce intermediate hashes values.


The function integrates the previous partial blocks placed in the
internal buffer of the SM3_CTX_mb16 context with the input messages
streams. Then, produces intermediate hashes values if the summary
lengths are bigger than SM3 block size. The remainder of the data, which
is not a multiple of the SM3 block size, is added to the internal buffer
for the further hashing.


Return Values
-------------


The mbx_sm3_update_mb16 function returns the status the indicates
whether the operation completed successfully or not. The status value of
0 indicates that hash values were updated successfully. In case of
non-zero status value, MBX_GET_HIGH_PART_STS16() and
MBX_GET_LOW_PART_STS16() can help to get the low and high parts of the
mbx_status16 , which can be analyzed separately with MBX_GET_STS() call.
The low part includes first eight statuses, while the high part includes
remaining eight statuses for each operation.

