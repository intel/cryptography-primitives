.. _rsa-algorithm-functions-mbx:


RSA Algorithm Functions (MBX)
=============================


RSA Notation
------------


The following description uses PKCS #1 v2.1: RSA Cryptography Standard
conventions:


-  ``n`` - RSA modulus
-  ``e`` - RSA public exponent
-  ``d`` - RSA private exponent,
   ``e*d = mod lambda(n), lambda(n) = LCM``
-  ``(n, e)`` - RSA public key
-  a pair ``(n, d)`` - so-called 1-st representation of the RSA private
   key
-  ``p, q`` - two prime factors of the RSA modulus ``n, n = p*q``
-  ``dP`` - the ``p``'s CRT exponent, ``e*dP = 1 mod(p-1)``
-  ``dQ`` - the ``q``'s CRT exponent, ``e*dQ = 1 mod(q-1)``
-  ``qInv`` - the CRT coefficient, ``q*qInv = 1 mod(p)``
-  a quintuple ``(p, q, dP, dQ, qInv)`` - so-called 2-nd representation
   of the RSA private key


All the numbers above are positive integers.


Keep in mind the following assumptions:


-  Current implementation supports RSA-1024, RSA-2048, RSA-3072 and
   RSA-4096 (the number denotes size of RSA modulus in bits)
-  Public exponent is fixed, e=65537
-  No specific assumption relatively "``d``", except bitsize(d) ~
   bitsize(n) and ``d<n``
-  Size of ``p`` and ``q`` in bits is approximately the same and equals
   bitsize(n)/2


RSA public key operation
------------------------


``y = x``\ :sup:`e`\ ``mod n, x`` and ``y`` are plane- and ciphertext
correspondingly


RSA private key (1-st representation) operation
-----------------------------------------------


``x = y``\ :sup:`d`\ ``mod n, y`` and ``x`` are cipher- and plaintext
correspondingly


RSA private key (2-nd representation) operation or CRT-based RSA private key operation
--------------------------------------------------------------------------------------


``x1 = y``\ :sup:`dP`\ ``mod p``


``x2 = y``\ :sup:`dQ`\ ``mod q``


``t = (x1-x2) * qInv mod p``


``x = x2 + q*t``

.. toctree::
   :maxdepth: 1

   
   mbx_rsa_public
   mbx_rsa_private
   mbx_rsa_private_crt
   mbx_rsa_method_bufsize