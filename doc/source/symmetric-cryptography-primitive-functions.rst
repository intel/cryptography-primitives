.. _symmetric-cryptography-primitive-functions:

Symmetric Cryptography Primitive Functions
==========================================


In the context of secure data communication, symmetric cryptography
primitive functions protect messages transferred over open communication
media by offering adequate security strength to meet application
security requirement, as well as algorithmic efficiency to enable secure
communication in real time.


Intel® Cryptography Primitives Library
offers operations using the following symmetric cryptography algorithms:


-  Block ciphers: Rijndael
   :term:`AES <[AES]>`,
   including AES-CCM :term:`NIST SP 800-38C <[NIST SP 800-38C]>`
   and AES-GCM :term:`NIST SP 800-38D <[NIST SP 800-38D]>`,
   Triple DES (TDES) :term:`FIPS PUB 46-3 <[FIPS PUB 46-3]>`,
   and SMS4
   :term:`SMS4 <[SMS4]>`.
-  Stream ciphers: ARCFour
   :term:`AC <[AC]>`,
   producing the same encryption/decryption as the RC4\* proprietary
   cipher of RSA Security Inc.

.. toctree::
   :maxdepth: 1


   block-cipher-modes-of-operation
   aes/rijndael-functions
   aes/aes-ccm-functions
   aes/aes-gcm-functions
   aes/aes-siv-functions
   aes/aes-xts-functions
   tdes-functions
   sms4-functions
   arcfour/arcfour-functions