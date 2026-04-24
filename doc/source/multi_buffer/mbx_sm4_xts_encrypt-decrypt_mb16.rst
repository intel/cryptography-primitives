.. _mbx_sm4_xts_encrypt-decrypt_mb16:

mbx_sm4_xts_encrypt/decrypt_mb16
================================


Encrypts plaintext (xts_encrypt) and decrypts ciphertext (xts_decrypt).


Syntax
------

mbx_status16 mbx_sm4_xts_encrypt_mb16(int8u\* pa_out[SM4_LINES],
const int8u\* pa_in[SM4_LINES],
const int len[SM4_LINES],
const mbx_sm4_key_schedule\* key_sched1,
const mbx_sm4_key_schedule\* key_sched2,
const int8u\* pa_tweak[SM4_LINES]);

mbx_status16 mbx_sm4_xts_decrypt_mb16(int8u\* pa_out[SM4_LINES],
const int8u\* pa_in[SM4_LINES],
const int in_len[SM4_LINES],
const mbx_sm4_key_schedule\* key_sched1,
const mbx_sm4_key_schedule\* key_sched2,
const int8u\* pa_tweak[SM4_LINES]);	

Include Files
-------------


``crypto_mb/sm4.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_out   
     -  Array of pointers up to 16 output data streams.
   * -     pa_in   
     -  Array of pointers up to 16 input data streams.
   * -     len   
     -  Array of lengths of the input data in bytes for up to 16 buffers.
   * -     key_sched1   
     -  Array of scheduled keys (from first 16 bytes of key) for up to 16 buffers.
   * -     key_sched2   
     -  Array of scheduled keys (from second 16 bytes of key) for up to 16 buffers.
   * -     pa_tweak   
     -  Array of pointers to the 16-byte tweaks (similar to IV) for up to 16 buffers.

Description
-----------


These functions encrypt/decrypt the input data streams passed by pa_in of a variable 
length (up to ``2^32 -1`` bytes) passed through len array according to the XTS cipher 
scheme and store the results into the memory buffers specified in pa_out parameter.

Return Values
-------------


The mbx_sm4_set_key_mb16() function returns the status that indicates
whether the operation completed successfully or not. The status value of
0 indicates that the key schedule was successfully initialized. In case
of non-zero status value, MBX_GET_HIGH_PART_STS16() and
MBX_GET_LOW_PART_STS16() can help to get the low and high parts of the
mbx_status16, which can be analyzed separately with MBX_GET_STS() call.
The low part includes first eight statuses, while the high part includes
remaining eight statuses for each operation.

