.. _sm2-elliptic-curve-functions:



SM2 Elliptic Curve Functions
============================


Elliptic Curve Notation
-----------------------


There are several ways of defining equation for elliptic curves, but
this section deals with Weierstrass equations. For the prime finite
field GF(p), p>3, the Weierstrass equation is E : y = x + a*x + b, where
a and b are integers modulo p. The number of points on the elliptic
curve E is denoted by #E.


For purpose of cryptography some additional parameters are presented:

-  n - prime divisor of #E and the order of point G
-  G - the point on curve E generated subgroup of the order n


The set of p, a, b, n, and G parameters are Elliptic Curve (EC) domain
parameter.


Elliptic Curve Key Pair
-----------------------


Private key is a positive integer u in the range [1, n-1]. Public key V,
which is the point on elliptic curve E, where V = [u] \* G. In
cryptography, there are two types of keypairs: regular (long-term) and
ephemeral (nonce - number that can only be used once). From the math
point of view, they are similar.


Supported Algorithms:
---------------------

-  Public key generation
-  ECDHE generation of shared secret
-  SM2 ECDSA signature generation
-  SM2 ECDSA signature verification

.. toctree::
   :maxdepth: 1

   
   mbx_sm2_ecdsa_sign
   mbx_sm2_ecdsa_verify
   mbx_sm2_ecpublic_key
   mbx_sm2_ecdh