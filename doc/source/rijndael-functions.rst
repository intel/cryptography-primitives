.. _rijndael-functions:



Rijndael Functions
==================


Rijndael cipher scheme is an iterated block cipher with a variable block
size and a variable key length.


Rijndael functions with the 128-bit key length are, in fact, Advanced
Encryption Standard (AES) cipher functions implemented in the way to
comply with the American Standard FIPS 197.


The AES\* functions use the ``IppsAESSpec`` context. This context serves as
an operational vehicle to carry not only a set of round keys and a set
of round inverse keys at the same time, but also the key management
information.


Once the respective initialization function generates the round keys,
the functions for ECB, CBC, CFB, and other modes are ready for either
encrypting or decrypting the streaming data.


The application code for conducting a typical encryption under CBC mode
using the AES scheme, that is, the Rijndael128 with a 128-bit key,
should follow the sequence of operations as outlined below:


#. Get the size required to configure the context ``IppsAESSpec`` by calling
   the function
   :ref:`AESGetSize <aesgetsize>`.
#. Call the operating system memory-allocation service function to
   allocate a buffer whose size is no less than the one specified by the
   function ``AESGetSize``.
#. Initialize the context IppsAESSpec\*pCtx by calling the function
   :ref:`AESInit <aesinit>`
   with the allocated buffer and the respective 128-bit AES key.
#. Specify the initialization vector and call the function
   :ref:`AESEncryptCBC <aesencryptcbc>`
   to encrypt the input data stream using the AES encryption function
   with CBC mode.
#. Clean up secret data stored in the context.
#. Call the operating system memory free service function to release the
   buffer allocated for the context ``IppsAESSpec``, if needed.


The IppsAESSpec context is position-dependent. The
:ref:`AESPack/AESUnpack <aespack-aesunpack>`
function transforms the respective position-dependent context to a
position-independent form and vice versa.

.. toctree::
   :maxdepth: 1


   aesgetsize
   aesinit
   aessetkey
   aespack-aesunpack
   aesencryptecb
   aesdecryptecb
   aesencryptcbc
   aesdecryptcbc
   aesencryptcbc_cs
   aesdecryptcbc_cs
   aesencryptcfb
   aes_encryptcfb16_mb
   aesdecryptcfb
   aesencryptofb
   aesdecryptofb
   aesencryptctr
   aesdecryptctr
   aesencryptxts_direct-aesdecryptxts_direct
   example-of-using-aes-functions
