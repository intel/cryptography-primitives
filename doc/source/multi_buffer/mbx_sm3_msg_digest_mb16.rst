.. _mbx_sm3_msg_digest_mb16:


mbx_sm3_msg_digest_mb16
=======================


Computes SM3 digest values of the input messages with known length.


Syntax
------


mbx_status16 mbx_sm3_msg_digest_mb16(const int8u \*pa_msg[16],
intlen[16], int8u \*pa_hash[16]);


Include Files
-------------


``crypto_mb/sm3.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_msg   
     -  Array of pointers to the input message.
   * -     len   
     -  Array of message lengths in bytes.
   * -     pa_hash   
     -  Array of pointers to the resultant digests.




Description
-----------


The function uses the SM3 hashing scheme to compute digest values of the
entire (non-streaming) input messages passed by pa_msg parameter in
parallel. The lengths of the messages are specified in len array and can
be different in different buffers. Produced hash values are stored in
the memory locations specified by the pa_hash parameter.


Return Values
-------------


The mbx_sm3_msg_digest_mb16 function returns the status that indicates
whether the operation completed successfully or not. The status value of
0 indicates that digest values for all messages were computed
successfully. In case of non-zero status value,
MBX_GET_HIGH_PART_STS16() and MBX_GET_LOW_PART_STS16() can help to get
the low and high parts of the mbx_status16 , which can be analyzed
separately with MBX_GET_STS() call. The low part includes first eight
statuses, while the high part includes remaining 8 statuses for each
operation.

