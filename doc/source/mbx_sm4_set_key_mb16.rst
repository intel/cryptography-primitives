.. _mbx_sm4_set_key_mb16:

mbx_sm4_set_key_mb16
====================


Initializes multi buffer key schedule to provide all necessary key
material for both encryption and decryption operations.


Syntax
------


mbx_status16 mbx_sm4_set_key_mb16(mbx_sm4_key_schedule\* key_sched,
const sm4_key\* pa_key[SM4_LINES]);


Include Files
-------------


``crypto_mb/sm4.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     key_sched   
     -  Pointer to key schedule being initialized.
   * -     pa_key   
     -  Array of pointers to the SM4 secret keys.




Description
-----------


Sets up mbx_sm4_key_schedule key schedule pointed by key_sched using
user-supplied secret keys passed through pa_key with all necessary key
material for both encryption and decryption operations.


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

