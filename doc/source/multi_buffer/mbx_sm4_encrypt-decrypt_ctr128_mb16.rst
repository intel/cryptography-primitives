.. _mbx_sm4_encrypt-decrypt_ctr128_mb16:


mbx_sm4_encrypt/decrypt_ctr128_mb16
===================================


Encryption/decryption of the input data streams by using the SM4
algorithm in the CTR mode with 128-bit counter.


Syntax
------


mbx_status16 mbx_sm4_encrypt_ctr128_mb16(int8u\* pa_out[SM4_LINES],
const int8u\* pa_inp[SM4_LINES], const int len[SM4_LINES], const
mbx_sm4_key_schedule\* key_sched, int8u\* pa_ctr[SM4_LINES]);


mbx_status16 mbx_sm4_decrypt_ctr128_mb16(int8u\* pa_out[SM4_LINES],
const int8u\* pa_inp[SM4_LINES], const int len[SM4_LINES], const
mbx_sm4_key_schedule\* key_sched, int8u\* pa_ctr[SM4_LINES]);


Include Files
-------------


``crypto_mb/sm4.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_out   
     -  Array of pointers to the output data streams.
   * -     pa_inp   
     -  Array of pointers to the input data streams.
   * -     len   
     -  Array of lengths of the input data in bytes.
   * -     key_sched   
     -  Pointer to key schedule.
   * -     pa_ctr   
     -  Array of pointers to the 128-bit initialization vectors for the CTR mode operation.




Description
-----------


These functions encrypt/decrypt the input data streams passed by pa_inp
of a variable length passed through len array according to the CTR
cipher scheme with 128-bit counters pa_ctr. The results are stored into
the memory buffers specified in pa_out parameter.


Return Values
-------------


The mbx_sm4_encrypt/decrypt_ctr128_mb16() function returns the status
that indicates whether the operation completed successfully or not. The
status value of 0 indicates that data streams were successfully
encrypted/decrypted. In case of non-zero status value,
MBX_GET_HIGH_PART_STS16() and MBX_GET_LOW_PART_STS16() can help to get
the low and high parts of the mbx_status16, which can be analyzed
separately with MBX_GET_STS() call. The low part includes first eight
statuses, while the high part includes remaining 8 statuses for each
operation.

