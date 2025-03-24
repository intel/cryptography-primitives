.. _mbx_sm4_gcm_encrypt_decrypt_mb16:

mbx_sm4_gcm_encrypt/decrypt_mb16
================================

Processes additional authenticated data (AAD).

Syntax
------

mbx_status16 mbx_sm4_gcm_encrypt_mb16(int8u* pa_out[SM4_LINES], const int8u* pa_in[SM4_LINES], const int in_len[SM4_LINES], SM4_GCM_CTX_mb16* p_context);

mbx_status16 mbx_sm4_gcm_decrypt_mb16(int8u* pa_out[SM4_LINES], const int8u* pa_in[SM4_LINES], const int in_len[SM4_LINES], SM4_GCM_CTX_mb16* p_context);


Include Files
-------------

``crypto_mb/sm4_gcm.h``

Parameters
----------

.. list-table::
   :header-rows: 0

   * - pa_out
     - Array of pointers to the output data streams.
   * - pa_in
     - Array of pointers to the input data streams.
   * - in_len
     - Array of lengths of the input data in bytes.
   * - p_context
     - Pointer to the context to keep intermediate results between calls.

Description
-----------

These functions encrypt/decrypt the input data streams passed by ``pa_in`` of a variable length passed through the ``in_len`` array according
to the GCM cipher scheme and store the results into the memory buffers specified in the ``pa_out`` parameter.
The functions also update the context with intermediate hash value.

.. note:: ``mbx_sm4_gcm_encrypt_mb16a`` and ``mbx_sm4_gcm_decrypt_mb16`` have several call sequence restrictions. See :ref:`sm4_gsm_algorithm_functions` page for details.

Return Values
-------------

The ``mbx_sm4_gcm_encrypt_mb16/mbx_sm4_gcm_decrypt_mb16()`` functions return the status that indicates whether the operation is completed successfully or not.
The status value of 0 indicates that the key schedule is successfully initialized. In case of a non-zero status value, ``MBX_GET_HIGH_PART_STS16()`` and
``MBX_GET_LOW_PART_STS16()`` can help to get the low and high parts of ``mbx_status16``, which can be analyzed separately with the ``MBX_GET_STS()`` call.
The low part includes the first eight statuses, while the high part includes the remaining eight statuses for each operation.
