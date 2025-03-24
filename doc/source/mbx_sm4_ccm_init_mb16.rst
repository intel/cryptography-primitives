.. _mbx_sm4_ccm_init_mb16:

mbx_sm4_ccm_init_mb16
=====================

Initializes context by setting up all necessary key material for both encryption and decryption operations and sets some internal parameters.

Syntax
------

mbx_status16 mbx_sm4_ccm_init_mb16(const sm4_key * pa_key[SM4_LINES], const int8u * pa_iv[SM4_LINES], const int iv_len[SM4_LINES], const int tag_len[SM4_LINES],
const int64u msg_len[SM4_LINES], SM4_CCM_CTX_mb16 * p_context);



Include Files
-------------

``crypto_mb/sm4_ccm.h``

Parameters
----------

.. list-table:: 
   :header-rows: 0

   * - pa_key
     - Array of pointers to the SM4 secret keys.
   * - pa_iv
     - Array of pointers to the initialization vectors.
   * - iv_len  
     - Array of lengths of the initialization vectors in bytes.
   * - tag_len
     - Array of lengths of the authentication tags in bytes
   * - msg_len  
     - Array of lengths of the messages in bytes.
   * - p_context
     - Pointer to the context to keep intermediate results between calls.



Description
-----------
Sets up a key schedule using user-supplied secret keys passed through ``pa_key`` with all necessary key material for both encryption and decryption operations. 
Processes the initialization vector streams passed by ``pa_iv`` of a variable length passed through ``iv_len`` array according to the CCM cipher scheme and updates context with processing result.

Return Values
-------------

The ``mbx_sm4_ccm_init_context_mb16()`` function returns the status that indicates whether the operation is completed successfully or not. 
The status value of 0 indicates that the key schedule is successfully initialized. In case of a non-zero status value, ``MBX_GET_HIGH_PART_STS16()``
and ``MBX_GET_LOW_PART_STS16()`` can help to get the low and high parts of the ``mbx_status16``, which can be analyzed separately with ``MBX_GET_STS()`` call. 
The low part includes the first eight statuses, while the high part includes the remaining eight statuses for each operation.
