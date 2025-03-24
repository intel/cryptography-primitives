.. _nist-recommended-elliptic-curve-functions:


NIST Recommended Elliptic Curve Functions
=========================================


Elliptic Curve Notation
-----------------------


There are several kinds of defining equation for elliptic curves, but
this section deals with *Weierstrass equations*. For the prime finite
field ``GF(p), p>3``, the Weierstrass equation
is \ ``E : y``\ :sup:`2`\ ``= x``\ :sup:`3`\ ``+ a*x + b``, where ``a``
and ``b`` are integers modulo ``p``. Number of points on the elliptic
curve ``E`` is denoted by ``#E``.


For purpose of cryptography some additional parameters are presented:


-  ``n`` - prime divisor of ``#E`` and the order of point ``G``
-  ``G`` - the point on curve ``E`` generated subgroup of the order n


The set of \ ``p, a, b, n`` and ``G`` parameters are Elliptic Curve (EC)
domain parameter. This section deals with three NIST recommended
Elliptic Curves those domain parameters are known and published in
[`SEC2 <https://www.secg.org/SEC2-Ver-1.0.pdf>`__] (Standards for
Efficient Cryptography Group, "Recommended Elliptic Curve Domain
Parameters", SEC 2, September 2000).


Elliptic Curve Key Pair
-----------------------


Private key is a positive integer ``u`` in the range ``[1, n-1]``.
Public key ``V``, which is the point on elliptic curve ``E``, where
``V = [u]*G``. In cryptography, there are two types of key pairs:
regular (or longterm) and ephemeral (or nonce - number that can only be
used once). From the math point of view, they are similar.


ECDSA signature generation
--------------------------


Input:


-  The EC domain parameters ``p, a, b, n`` and ``G``
-  The signer's regular ``u`` and ephemeral ``k`` private keys
-  The message representative, which is an integer ``f>=0``


Output: The signature, which is a pair of integers ``(r, s)``, where
``r`` and ``s`` belongs the range ``[1. r-1]``.


Operation:


#. Compute an ephemeral public key ``K = [k]G. Let K = (x, y)``
#. Compute an integer \ ``r = x mod n``
#. Compute an integer ``s = (k``\ :sup:`-1`\ ``)*(f + u*r) mod n``
#. Return ``(r, s)`` as signature


ECDHE generation of shared secret
---------------------------------


Input:


-  The EC domain parameters ``p, a, b, n`` and ``G``
-  The own ephemeral private key ``u``
-  The party's ephemeral public key ``W``


Output: The derived shared secret value ``z``, which is the \ ``GF(p)``
field element


Operation:


#. Compute an EC point ``P = [u]W, P=(xp, yp)``
#. Let \ ``z = xp``
#. Return shared secret ``z``

.. toctree::
   :maxdepth: 1

   
   mbx_nistp256-384-521_ecdsa_sign_setup
   mbx_nistp256-384-521_ecdsa_sign_complete
   mbx_nistp256-384-521_ecdsa_sign
   mbx_nistp256-384-521_ecdsa_verify
   mbx_nistp256-384-521_ecpublic_key
   mbx_nistp256-384-521_ecdh
