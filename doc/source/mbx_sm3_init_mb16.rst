.. _mbx_sm3_init_mb16:

mbx_sm3_init_mb16
=================


Initializes the SM3 multi-buffer context for future use.


Syntax
------


mbx_status16 mbx_sm3_init_mb16 (SM3_CTX_mb16\*p_state);


Include Files
-------------


``crypto_mb/sm3.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     p_state   
     -  Pointer to the SM3_CTX_mb16 context being initialized.




Description
-----------


The function sets up the SM3_CTX_mb16 digest context pointed by p_state.


Return Values
-------------


The mbx_sm3_init_mb16 function returns the status that indicates whether
the operation completed successfully or not. The status value of 0
indicates that the context was initialized successfully. In case of
non-zero status value, MBX_GET_HIGH_PART_STS16() and
MBX_GET_LOW_PART_STS16() can help to get the low and high parts of the
mbx_status16 , which can be analyzed separately with MBX_GET_STS() call.
The low part includes first eight statuses, while the high part includes
remaining eight statuses for each operation.

