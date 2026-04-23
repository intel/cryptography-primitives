.. _arcfour-functions:


ARCFour Functions
=================


.. note::


   ARCFour algorithm functions are deprecated and will be removed in a
   future Intel® Cryptography Primitives Library release.


As the RC4\* stream cipher, widely used for file encryption and secure
communications, is the property of RSA Security Inc., a cipher discussed
in this section and resulting in the same encryption/decryption as RC4\*
is called ARCFour.


The ARCFour stream cipher
:term:`AC <[AC]>` uses a
variable length key of up to 256 octets (bytes). ARCFour operates in the
Output Feedback mode (OFB), defined in :term:`NIST SP 800-38A <[NIST SP 800-38A]>`,
which creates the keystream independently of both the plaintext and the
ciphertext.


The ARCFour algorithm functions, described in this section, use the
context IppsARCFourState as an operational vehicle to carry variables
needed to execute the algorithm: S-Boxes and a current pair of indices.


The typical application code for conducting an encryption or decryption
using ARCFour should follow the sequence of operations listed below:


#. Get the buffer size required to configure the context
   IppsARCFourState by calling the function
   :ref:`ARCFourGetSize <arcfourgetsize>`.
#. Call the operating system memory allocation service function to
   allocate a buffer whose size is not less than the one specified by
   the function
   :ref:`ARCFourGetSize <arcfourgetsize>`.
#. Initialize the pointer pCtx to the IppsARCFourState context by
   calling the function
   :ref:`ARCFourInit <arcfourinit>`
   with the allocated buffer and the respective ARCFour cipher key of
   the specified size.
#. Call the
   :ref:`ARCFourEncrypt <arcfourencrypt>`
   or
   :ref:`ARCFourDecrypt <arcfourdecrypt>`
   function to encrypt or decrypt the input data stream, respectively.
#. Clean up secret data stored in the context.
#. Call the operating system memory free service function to release the
   buffer allocated for the IppsARCFourState context, if needed.


The ARCFourSpec context is position-dependent. The
:ref:`ARCFourPack/ARCFourUnpack <arcfourpack-arcfourunpack>`
functions transform the position-dependent context to a
position-independent form and vice versa.

.. rubric:: Related Information

:ref:`data-security-considerations`


.. toctree::
   :maxdepth: 1


   arcfourgetsize
   arcfourcheckkey
   arcfourinit
   arcfourpack-arcfourunpack
   arcfourencrypt
   arcfourdecrypt
   arcfourreset
