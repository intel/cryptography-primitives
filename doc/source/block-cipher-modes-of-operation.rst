.. _block-cipher-modes-of-operation:

Block Cipher Modes of Operation
===============================


Most of Symmetric Cryptography Algorithms implemented in Intel® Cryptography Primitives Library are
Block Ciphers, which operate on data blocks of the fixed size. Block
Ciphers encrypt a plaintext block into a ciphertext block or decrypts a
ciphertext block into a plaintext block. The size of the data blocks
depends on the specific algorithm. The table below shows the
correspondence between Block Ciphers applied and their data block size.


.. list-table:: Block Sizes in Symmetric Algorithms
   :header-rows: 1

   * -  Block Cipher Name
     -  Data Block Size (bits)
   * -  Rijndael128 (AES)
     -  128
   * -  TDES
     -  64
   * -  SMS4
     -  128




Block Cipher modes of executing the operation of encryption/decryption
are applied in practice more frequently than “pure” Block Ciphers. On
one hand, the modes enable you to process arbitrary length data stream.
On the other hand, they provide additional security strength.


Intel® Cryptography Primitives Library supports five widely used modes, as specified
in :term:`NIST SP 800-38A <[NIST SP 800-38A]>`:


-  Electronic Code Book (ECB) mode


-  Cipher Block Chain (CBC) mode


-  Cipher Feedback (CFB) mode


-  Output Feedback (OFB) mode


-  Counter (CTR) mode.


Using the OFB mode
------------------


Intel® Cryptography Primitives Library function APIs of the OFB mode contain the ``ofbBlkSize``
parameter, which represents size of the feedback. Possible size values
vary between 8 and ``B``\ \*8 bits, where ``B`` is the data block size
of the underlying cipher. For cryptographic strength reasons, avoid
using ``ofbBlkSize`` smaller than ``B``\ \*8 bits.


Using the CTR mode
------------------


Intel® Cryptography Primitives Library calls performing encryption and decryption treat the processed
message ``msg``, with a length of ``msgLen``, as an integral data unit. This means the
ippsAESEncryptCTR or ippsAESDencryptCTR function processes the whole
message in a single call.


If an application cannot encrypt or decrypt the message in a single
call, the input data M can be treated as a set of blocks


M = M\ :sub:`0`\ \| \|M\ :sub:`1`\ \| \|...M\ :sub:```n``-1`\ \|
\|M\ :sub:`n`


where:

-  ``n`` is the largest integer so that ``B``\ \*\ ``n`` is not bigger
   than the M size;
-  lengths of the first ``n`` blocks M\ :sub:`0`, ..., M\ :sub:```n``-1`
   are multiple to the data block size ``B`` of the underlying cipher;
-  size of the last block M\ :sub:`n` is between 0 and ``B``-1 bytes.


In this case, the application processes the message M using a sequence
of Intel® Cryptography Primitives Library encryption or decryption calls.


The cryptographic functions described in this section require the
application to specify both the plaintext message and the ciphertext
message lengths as multiples of block size of the respective algorithm
(see :ref:`block-cipher-modes-of-operation`). To meet
this requirement in ciphering the message, the application may use any
padding scheme, for example, the scheme defined in
:term:`PKCS7 <[PKCS 7]>`. In
case padding is used, the application is responsible for correct
interpretation and processing of the last deciphered message block. So
of the three padding schemes available for earlier releases,


.. code-block:: cpp


   typedef enum {
        NONE  = 0, IppsCPPaddingNONE = 0,
        PKCS7 = 1, IppsCPPaddingPKCS7 = 1,
        ZEROS = 2, IppsCPPaddingZEROS = 2
    } IppsCPPadding;  


only ``IppsCPPaddingNONE`` remains acceptable.

