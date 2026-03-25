.. _index:

Developer Guide and Reference for Intel® Cryptography Primitives Library
========================================================================

To see what is new with the latest release, see the `Release Notes <https://www.intel.com/content/www/us/en/developer/articles/release-notes/cryptography-primitives-library.html>`__


Intel® Cryptography Primitives Library is a software
library that provides a comprehensive set of application domain-specific
highly optimized functions for cryptography.


.. note::


   This publication, the *Developer Guide and Reference for Intel® Cryptography Primitives Library*,
   was previously known as *Developer Guide and Reference for Intel® Integrated Performance Primitives Cryptography*.
   Versions 2021.12 and older of this document can be found at
   `Developer Guide and Reference for Intel® Integrated Performance Primitives Cryptography <https://www.intel.com/content/www/us/en/docs/ipp-crypto/developer-guide-reference/2021-12/overview.html>`_.


Intel® Cryptography Primitives Library
======================================

Intel® Cryptography Primitives Library is a library that offers
users a cross-platform and cross operating system application programming
interface (API) for routines commonly used for cryptographic operations.
Among other features, the library includes:

RSA Algorithm Functions
-----------------------


:ref:`RSA Algorithm Functions <rsa-algorithm-functions>` implement the
non-symmetric cryptography RSA algorithm. Subsections include reference for
different encryption schemes and RSA system building functions.


Rijndael Functions
------------------


:ref:`Rijndael Functions <rijndael-functions>`
implement the symmetric iterated Rijndael block cipher with variable key
and block sizes. The Rijndael cipher with 128 bit block size is also
known as the Advanced Encryption Standard (AES) cipher.


Mask Generation Functions
-------------------------


A Mask Generation Function takes a string of arbitrary length and
deterministically outputs a pseudorandom string of desired length. :ref:`Mask
Generation Functions <mask-generation-functions>`
are used in different cryptographic algorithms, including some RSA
encryption schemes.


AES-CCM Functions
-----------------


:ref:`AES-CCM Functions <aes-ccm-functions>`
are an implementation of the Counter with Cipher Block Chaining-Message
Authentication Code (CCM) mode of operation of the AES cipher.


AES-GCM Functions
-----------------


:ref:`AES-GCM Functions <aes-gcm-functions>`
implement the Galois/Counter Mode (GCM) of operation of the AES block
cipher. GCM is an authenticated encryption algorithm, which allows you
to verify the integrity of encrypted data.


Post-quantum Functions
----------------------


:ref:`Post-quantum Functions <post-quantum-functions>`
implement post-quantum algorithm functions.


.. admonition:: Product and Performance Information

   Performance varies by use, configuration and other factors. Learn more at https://edc.intel.com/content/www/us/en/products/performance/benchmarks/overview/.
   Notice revision #20201201


Documentation for older versions of Intel® Cryptography Primitives Library are available for download only. For a list of
available documentation downloads by product version, see these pages:


-  `Download Documentation for Intel® Parallel Studio XE <https://www.intel.com/content/www/us/en/developer/articles/guide/download-documentation-intel-parallel-studio-xe-current-previous.html>`_
-  `Download Documentation for Intel® System Studio <https://www.intel.com/content/www/us/en/developer/articles/guide/download-documentation-intel-system-studio-current-previous.html>`_


.. toctree::
   :maxdepth: 1


   introducing-intel-cryptography-primitives
   notational-conventions
   theory-of-operation
   getting-started
   using-custom-library-tool-for-intel-cryptography
   performance-test-tool-perfsys-cli-options
   preview-features
   developer-reference
   getting-help-and-support
   notices-and-disclaimers
