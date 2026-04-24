.. _mbx_sm4_xts_set_keys_mb16:

mbx_sm4_xts_set_keys_mb16
=========================


Schedules two 16-byte keys from a 32-byte key, for 16 buffers, prior to encryption/decryption.


Syntax
------


mbx_status16 mbx_sm4_xts_set_keys_mb16(mbx_sm4_key_schedule\* key_sched1, 
mbx_sm4_key_schedule\* key_sched2,
const sm4_xts_key\* pa_key[SM4_LINES]);

Include Files
-------------


``crypto_mb/sm4.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     key_sched1   
     -  Array of scheduled keys (from first 16 bytes of key) for up to 16 buffers.
   * -     key_sched2   
     -  Array of scheduled keys (from second 16 bytes of key) for up to 16 buffers.
   * -     pa_key   
     -  Array of up to 16 pointers to the SM4-XTS 32-byte secret keys.


Description
-----------


Sets up key schedule using user-supplied secret keys passed through pa_key with all 
necessary key material for both encryption and decryption operations. 
It uses the first 16 bytes of each 32-byte key to schedule key_sched1 and the 
second 16 bytes of each 32-byte key to schedule key_sched2.


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

