.. _aes-ccm-functions:


AES-CCM Functions
=================


This section describes functions for authenticated encryption/decryption
using the Counter with Cipher Block Chaining-Message Authentication Code
(CCM) mode :term:`NIST SP 800-38C <[NIST SP 800-38C]>`
of the AES (Rijndael128) block cipher.


The AES-CCM functions enable authenticated encryption/decryption of
several messages using one key that the
:ref:`AES_CCMInit <aes_ccminit>`
function sets. Processing of each new message starts with a call to the
:ref:`AES_CCMStart <aes_ccmstart>` function. The application code for
conducting a typical AES-CCM
authenticated encryption should follow the sequence of operations as
outlined below:


#. Get the size required to configure the context IppsAES_CCMState by
   calling the function
   :ref:`AES_CCMGetSize <aes_ccmgetsize>`.
#. Call the system memory-allocation service function to allocate a
   buffer whose size is not less than the function AES_CCMGetSize
   specifies.
#. Initialize the context IppsAES_CCMState\*pCtx by calling the function
   :ref:`AES_CCMInit <aes_ccminit>`
   with the allocated buffer and respective AES key.
#. Optionally call
   :ref:`AES_CCMMessageLen <aes_ccmmessagelen>`
   and/or
   :ref:`AES_CCMTagLen <aes_ccmtaglen>`
   to set up message and tag parameters.
#. Call
   :ref:`AES_CCMStart <aes_ccmstart>`
   to start authenticated encryption of the first/next message.
#. Keep calling
   :ref:`AES_CCMEncrypt <aes_ccmencrypt>`
   until the entire message is processed.
#. Request the authentication tag by calling
   :ref:`AES_CCMGetTag <aes_ccmgettag>`.
#. Proceed to the next message, if any, that is, go to step 5.
#. Clean up secret data stored in the context.
#. Call the system memory free service function to release the buffer
   allocated for the context IppsAES_CCMState, if needed.

.. rubric:: Related Information

:ref:`data-security-considerations`

.. toctree::
   :maxdepth: 1


   aes_ccmgetsize
   aes_ccminit
   aes_ccmstart
   aes_ccmencrypt
   aes_ccmdecrypt
   aes_ccmgettag
   aes_ccmmessagelen
   aes_ccmtaglen
