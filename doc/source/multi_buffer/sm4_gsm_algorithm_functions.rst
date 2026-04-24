.. _sm4_gsm_algorithm_functions:

SM4 GCM Algorithm Functions
===========================

Functions described in this section can be used for the Galois/counter operational mode of SM4 cipher systems.

The implementation supports up to 16 buffers of input data. The implementation supports separated calls to provide
the ability to process the payload that is divided into several parts. For example, a plain text of 3kB size can be processed by 3 calls on 1 kB each
or 2 calls on 1 kB and 2 kB. Any other number of calls and any combinations of lengths are allowed if it is fit to call sequence restrictions.
The implementation uses a context to keep the intermediate results between calls.

Valid call sequence:

#. ``mbx_sm4_gcm_init_mb16``
#. ``mbx_sm4_gcm_update_iv_mb16`` (optional, can be called as many times as necessary)
#. ``mbx_sm4_gcm_update_aad_mb16`` (optional, can be called as many times as necessary )
#. ``mbx_sm4_gcm_encrypt_mb16/mbx_sm4_gcm_decrypt_mb16`` (optional, can be called as many times as necessary)
#. ``mbx_sm4_gcm_get_tag_mb16``

Call sequence restrictions:

* ``mbx_sm4_gcm_get_tag_mb16`` can be called after IV is fully processed. Therefore, if a buffer with a partial block (of less than 16 bytes size) is processed (by any of API mbx_sm4_gcm_init_mb16 or mbx_sm4_gcm_update_iv_mb16) or ``mbx_sm4_gcm_update_aad_mb16`` is called.
* At steps two to four, functions be called as many times as needed to process the payload, while these functions process buffers with full blocks (of 16 bytes size) or empty buffers and the length of the processed payload is not overflowed.
* If functions at steps two to four are called to process a partial block, they cannot be called again.
* If ``mbx_sm4_gcm_update_aad_mb16`` is called, ``mbx_sm4_gcm_update_iv_mb16`` cannot be called.
* If ``mbx_sm4_gcm_encrypt_mb16`` or ``mbx_sm4_gcm_decrypt_mb16`` is called, ``mbx_sm4_gcm_update_aad_mb16`` and ``mbx_sm4_gcm_update_iv_mb16`` cannot be called.
* If ``mbx_sm4_gcm_encrypt_mb16`` is called, ``mbx_sm4_gcm_decrypt_mb16`` cannot be called.
* If ``mbx_sm4_gcm_decrypt_mb16`` is called, ``mbx_sm4_gcm_encrypt_mb16`` cannot be called.

.. toctree::
   :maxdepth: 1

   mbx_sm4_gcm_init_mb16
   mbx_sm4_gcm_update_iv_mb16
   mbx_sm4_gcm_update_aad_mb16
   mbx_sm4_gcm_encrypt-decrypt_mb16
   mbx_sm4_gcm_get_tag_mb16

