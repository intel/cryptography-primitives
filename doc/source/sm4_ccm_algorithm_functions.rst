.. _sm4_ccm_algorithm_functions:

SM4 CCM Algorithm Functions
===========================

Functions described in this section can be used for the CCM operational mode of SM4 cipher systems.

The implementation supports up to 16 buffers of input data. The implementation uses a context to keep intermediate results between calls. 

Valid call sequence:

#. ``mbx_sm4_ccm_init_mb16``
#. ``mbx_sm4_ccm_update_aad_mb16`` (optional)
#. ``mbx_sm4_ccm_encrypt_mb16/mbx_sm4_ccm_decrypt_mb16`` (optional, can be called as many times as necessary)
#. ``mbx_sm4_ccm_get_tag_mb16``

Call sequence restrictions:

* ``mbx_sm4_ccm_get_tag_mb16`` can be called after ``mbx_sm4_ccm_init_mb16`` has been called.
* If ``mbx_sm4_ccm_update_aad_mb16`` is called, you cannot call it again.
* If ``mbx_sm4_ccm_encrypt_mb16`` or ``mbx_sm4_ccm_decrypt_mb16`` is called, you cannot call ``mbx_sm4_ccm_update_aad_mb16``.
* At step four: 

  * functions can be called as many times as needed to process the payload. These functions process buffers with full blocks (of 16 bytes size) or empty buffers and the length of the processed payload is not overflowed.
  * if functions are called to process a partial block, you cannot call it again.
  
* If ``mbx_sm4_ccm_encrypt_mb16`` is called, you cannot call ``mbx_sm4_ccm_decrypt_mb16``.
* If ``mbx_sm4_ccm_decrypt_mb16`` was called, you cannot call ``mbx_sm4_ccm_encrypt_mb16``.

.. toctree::
  :maxdepth: 1
   
  mbx_sm4_ccm_init_mb16
  mbx_sm4_ccm_update_aad_mb16
  mbx_sm4_ccm_encrypt_decrypt_mb16
  mbx_sm4_ccm_get_tag_mb16
