.. _mbx_sm3_final_mb16:


mbx_sm3_final_mb16
==================


Completes computation of the SM3 digest values.


Syntax
------


mbx_status16 mbx_sm3_final_mb16(int8u\*pa_hash[16],
SM3_CTX_mb16\*p_state);


Include Files
-------------


``crypto_mb/sm3.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_hash   
     -  Array of pointers to the resultant digests.
   * -     p_state   
     -  Pointer to the SM3_CTX_mb16 context.




Description
-----------


The function completes calculation of the digest values and stores the
results in the memory specified by the pa_hash parameter.


Return Values
-------------


The mbx_sm3_final_mb16 function returns the status that indicates
whether the operation completed successfully or not. The status value of
0 indicates that the computation of SM3 digest values was finalized
successfully. In case of non-zero status value,
MBX_GET_HIGH_PART_STS16() and MBX_GET_LOW_PART_STS16() can help to get
the low and high parts of the mbx_status16, which can be analyzed
separately with MBX_GET_STS() call. The low part includes first eight
statuses, while the high part includes remaining 8 statuses for each
operation.

