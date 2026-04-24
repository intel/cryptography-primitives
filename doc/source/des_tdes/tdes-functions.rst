.. _tdes-functions:



TDES Functions
==============


.. note::


   The TDES algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: AES. For more information, see
   *Transitioning the Use of Cryptographic Algorithms and Key Lengths*
   (https://csrc.nist.gov/CSRC/media/Publications/sp/800-131a/rev-2/draft/documents/sp800-131Ar2-draft.pdf),
   *Update to Current Use and Deprecation of TDEA*
   (https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA),
   *Sweet32: Birthday attacks on 64-bit block ciphers in TLS and
   OpenVPN*.


The Triple Data Encryption Algorithm (TDEA) is a revised symmetric
algorithm scheme built on the Data Encryption Standard (DES) system. The
Triple DES (TDES) encryption process includes three consecutive DES
operations in the encryption, decryption, and encryption (E-D-E)
sequence again in accordance with the American standard FIPS 46-3. While
AES (Rijndael) is preferred, TDEA is an approved cipher. Use
implementations of AES where possible. In cases where using AES is
impossible or inconvenient, use TDES functions.


Although the functions that support TDES operations require three sets
of round keys, the functions can operate under TDES cipher system with a
two-set round keys by simply setting the third set of round keys to be
the same as the first set.


You can use the functions described in this section for performing
various operational modes under the TDES cipher systems.


.. note::


   Intel® Cryptography Primitives Library functions do not allocate memory
   internally. The GetSize function does not require allocated memory.
   You need to call the GetSize function to find out how much available
   memory you need to have to work with the selected algorithm and after
   that you call the initialization function to create a memory buffer
   and initialize it.


Intel® Cryptography Primitives Library supports ECB, CBC, CFB, and CTR modes. You
can tell which algorithm a given function supports from the function
base name, for example, the
:ref:`TDESEncryptECB <tdesencryptecb>`
function operates under the ECB mode.


The encryption function
:ref:`TDESEncryptCBC <tdesencryptcbc>`
operates under the CBC mode using its cipher scheme and requires to have
an initialization vector iv. Since there are a number of ways to
initialize the initialization vector iv, you should remember which of
them you used to be able to decrypt the message when needed.


The encryption function
:ref:`TDESEncryptCFB <tdesencryptcfb>`
operates under the CFB mode using its cipher scheme and requires having
the initialization vector pIV and CFB block size cfbBlkSize.


All functions described in this section use the context IppsDESSpec to
serve as an operational vehicle that carries a set of round keys.


Application code for conducting a typical encryption under CBC mode
using the TDES scheme must perform the following sequence of operations:


#. Get the size required to configure the context IppsDESSpec by calling
   the function
   :ref:`DESGetSize <desgetsize>`.
#. Call operating system memory allocation service function to allocate
   three buffers whose sizes are not less than the one specified by the
   function DESGetSize. Initialize pointers to contexts pCtx1, pCtx2,
   and pCtx3 by calling the function
   :ref:`DESInit <desinit>`
   three times, each with the allocated buffer and the respective DES
   key.
#. Specify the initialization vector and then call the function
   :ref:`TDESEncryptCBC <tdesencryptcbc>`
   to encrypt the input data stream under CBC mode using TDES scheme.
#. Clean up secret data stored in the contexts.
#. Free the memory allocated to the buffer once TDES encryption under
   the CBC mode has been completed and the data structures allocated for
   set of round keys are no longer required.


.. note::


   Similar procedure can be applied for ECB, CFB, and CTR mode
   operation.


The IppsDESSpec context is position-dependent. The
:ref:`DESPack/DESUnpack <despack-desunpack>`
functions transform the position-dependent context to a
position-independent form and vice versa.


.. rubric:: Related Information

:ref:`data-security-considerations`



.. toctree::
   :maxdepth: 1


   desgetsize
   desinit
   despack-desunpack
   tdesencryptecb
   tdesdecryptecb
   tdesencryptcbc
   tdesdecryptcbc
   tdesencryptcfb
   tdesdecryptcfb
   tdesencryptofb
   tdesdecryptofb
   tdesencryptctr
   tdesdecryptctr
   example-of-using-tdes-functions
