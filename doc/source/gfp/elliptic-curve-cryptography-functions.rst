.. _elliptic-curve-cryptography-functions:



Elliptic Curve Cryptography Functions
=====================================


Intel® Cryptography Primitives Library
offers functions allowing for different operations with an
elliptic curve defined over a prime finite field GF(*p*).


The functions are based on standards :term:`IEEE P1363A <[IEEE P1363A]>`,
:term:`SEC1 <[SEC1]>`,
:term:`ANSI <[ANSI]>`, and
:term:`SM2 <[SM2]>`.


Intel® Cryptography Primitives Library supports some elliptic curves with fixed
parameters, the so-called standard or recommended curves. These
parameters are chosen so that they provide a sufficient level of
security and enable efficient implementation.

.. toctree::
   :maxdepth: 1


   functions-based-on-gf-p
   functions-based-on-sm2
   arithmetic-of-the-group-of-elliptic-curve-points
   eccgetresultstring