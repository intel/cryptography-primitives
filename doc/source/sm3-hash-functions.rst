.. _sm3-hash-functions:



SM3 Hash Functions
==================


SM3 functionality supports two scenarios of data processing:

#. Processing the entire messages with known length:
   :ref:`mbx_sm3_msg_digest_mb16() <mbx_sm3_msg_digest_mb16>`.
#. Streaming processing, when the lengths of the messages are initially
   unknown:
   :ref:`mbx_sm3_init_mb16() <mbx_sm3_init_mb16>`,
   :ref:`mbx_sm3_update_mb16() <mbx_sm3_update_mb16>`,
   :ref:`mbx_sm3_final_mb16() <mbx_sm3_final_mb16>`.


Functions that work in streaming mode operate with the public
SM3_CTX_mb16 context. “Public” means that the structure of this context
is open and fields of this context are accessible to users. For more
information refer to crypto_mb/sm3.h. To get started with this context,
you need to allocate memory for it and call the mbx_sm3_init_mb16()
function to set it up.

.. toctree::
   :maxdepth: 1


   mbx_sm3_msg_digest_mb16
   mbx_sm3_init_mb16
   mbx_sm3_update_mb16
   mbx_sm3_final_mb16