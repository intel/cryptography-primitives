.. _aes-gcm-functions:



AES-GCM Functions
=================


The Galois/Counter Mode (GCM) is a mode of operation of the AES
algorithm. GCM :term:`NIST SP 800-38D <[NIST SP 800-38D]>` uses
a variation of the Counter mode of operation for encryption. GCM assures
authenticity of the confidential data (of up to about 64 GB per
invocation) using a universal hash function defined over a binary finite
field (the Galois field).


GCM can also provide authentication assurance for additional data (of
practically unlimited length per invocation) that is not encrypted. If
the GCM input contains only data that is not to be encrypted, the
resulting specialization of GCM, called GMAC, is simply an
authentication mode for the input data.


GCM provides stronger authentication assurance than a
(non-cryptographic) checksum or error detecting code. In particular, GCM
can detect both accidental modifications of the data and intentional,
unauthorized modifications.


The AES-GCM function set includes incremental functions, which enable
authenticated encryption/decryption of several messages using one key.
The application code for conducting a typical AES-GCM authenticated
encryption should follow the sequence of operations as outlined below:


#. Get the size required to configure the context IppsAES_GCMState by
   calling the function
   :ref:`AES_GCMGetSize <aes_gcmgetsize>`.
#. Call the system memory-allocation service function to allocate a
   buffer whose size is not less than the function AES_GCMGetSize
   specifies.
#. Initialize the context IppsAES_GCMState\*pCtx by calling the function
   :ref:`AES_GCMInit <aes_gcminit>`
   with the allocated buffer and the respective AES key.
#. Call
   :ref:`AES_GCMStart <aes_gcmstart>`
   to start authenticated encryption of the first/next message.
#. Keep calling
   :ref:`AES_GCMEncrypt <aes_gcmencrypt>`
   until the entire message is processed.
#. Request the authentication tag by calling
   :ref:`AES_GCMGetTag <aes_gcmgettag>`.
#. Proceed to the next message, if any, that is, go to step 4.
#. Clean up secret data stored in the context.
#. Call the system memory free service function to release the buffer
   allocated for the context IppsAES_GCMState, if needed.


If the size of the initial vector and/or additional authenticated data
(IV and AAD parameters of the AES_GCMStart function, respectively) is
large or any of these parameters is placed in a disconnected memory
buffer, replace step 4 above with the following sequence:


#. Call
   :ref:`AES_GCMReset <aes_gcmreset>`
   to prepare the IppsAES_GCMState context for authenticated encryption
   of the first/new message.


#. Keep calling
   :ref:`AES_GCMProcessIV <aes_gcmprocessiv>`
   for successive parts of IV until the entire IV is processed.


#. Keep calling
   :ref:`AES_GCMProcessAAD <aes_gcmprocessaad>`
   for successive parts of AAD until the entire AAD is processed.


.. rubric:: Related Information

:ref:`data-security-considerations`

.. toctree::
   :maxdepth: 1


   aes_gcmgetsize
   aes_gcminit
   aes_gcmreinit
   aes_gcmstart
   aes_gcmreset
   aes_gcmprocessiv
   aes_gcmprocessaad
   aes_gcmencrypt
   aes_gcmdecrypt
   aes_gcmgettag
