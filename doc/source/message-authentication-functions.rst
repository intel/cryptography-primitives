.. _message-authentication-functions:



Message Authentication Functions
================================


Hash function-based MAC (HMAC) is widely used in the applications
requiring message authentication and data integrity check. HMAC was
initially put forward in :term:`RFC 2401 <[RFC 2401]>` and
adopted by ANSI X9.71 and :term:`FIPS PUB 198 <[FIPS PUB 198-1]>`. See
:ref:`Keyed Hash Functions <keyed-hash-functions>` for a
description of the Intel® Cryptography Primitives Library
HMAC primitives.


A MAC algorithm based on a symmetric key block cipher, in other words, a
cipher-based MAC (CMAC), is standardized in :term:`NIST SP 800-38B <[NIST SP 800-38B]>`.
CMAC may be appropriate for information systems where an approved block
cipher is available rather than an approved hash function. See
:ref:`CMAC Functions <cmac-functions>` for a
description of the Intel® Cryptography Primitives Library CMAC primitives.

.. toctree::
   :maxdepth: 1


   keyed-hash-functions
   cmac-functions