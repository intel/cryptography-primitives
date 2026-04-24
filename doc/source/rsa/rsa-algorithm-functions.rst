.. _rsa-algorithm-functions:


RSA Algorithm Functions
=======================


This section introduces Intel® Cryptography Primitives Library
functions for RSA algorithm. The section describes a
set of primitives to perform operations required for RSA cryptographic
systems. This set of primitives offers a flexible user interface that
enables scalability of the RSA crypto key size with the limit of up to
4096 bits.


According to :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`, a de
facto standard for RSA implementations, a pair of keys (public and
private) defines forward and inverse transforms of text (or operations
on a public and secret key). Mathematical expressions for the forward
and inverse transforms are similar. If ``x`` is plain text and ``y`` is
the corresponding ciphertext, the mathematical expressions are as
follows:


-  ``y = x^e mod n`` for the forward transform, or encryption


-  ``x = y^d mod n`` for the inverse transform, or decryption


In these expressions, ``e`` is the public exponent, ``d`` is the private
exponent, and ``n`` is the RSA modulus. To enable direct and inverse
transforms, a mathematical relationship exists between these values.


The (``n,e``) pair is called the public key. With the known modulus
``n``, the public or private exponent determines whether the RSA
cryptosystem is public or private. Intel® Cryptography Primitives Library supports these,
interrelated, representations of the private key:


-  Private key type 1 is the (``n,d``) pair.


-  Private key type 2 is the (``p,q,dP,dQ,qInv``) quintuple (for
   details, see :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`).


   This representation speeds computations by using the Chinese
   Remainder Theorem (CRT).


RSA algorithm functions include:


-  :ref:`Functions for Building RSA
   System <functions-for-building-rsa-system>`, the
   system being then used by functions listed below.
-  :ref:`RSA Primitives <rsa-primitives>`,
   which perform RSA encryption and decryption.
-  :ref:`RSA Encryption
   Schemes <rsa-encryption-schemes>` and :ref:`RSA
   Signature Schemes <rsa-signature-schemes>`, which
   combine RSA cryptographic primitives with other techniques, such as
   computing hash message digests or applying mask generation functions
   (MGFs), to achieve a particular security goal.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   To provide minimum security, the length of the RSA modulus must be
   equal to or greater than 1024 bits.

.. toctree::
   :maxdepth: 1


   functions-for-building-rsa-system
   rsa-primitives
   rsa-encryption-schemes
   rsa-signature-schemes
