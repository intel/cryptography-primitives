.. _mask-generation-functions:


Mask Generation Functions
=========================


Public Key Cryptography frequently uses mask generation functions (MGFs)
to achieve a particular security goal. For example, MGFs are used both
in RSA-OAEP encryption and RSA-SSA signature schemes.


MGF function takes an octet string of a variable length and generates an
octet string of a desired length. MGFs are deterministic, which means
that the input octet string completely determines the output one. The
output of an MGF should be pseudorandom, that is, infeasible to predict.
The provable security of such cryptography schemes as RSA-OAEP or
RSA-SSA relies on the random nature of the MGF output. That is why
one-way hash functions is one of the well-known ways to implement an
MGF. The exact definition of an MGF based on a one-way hash function may
be found in :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`.


This section describes MGFs based on widely-used hash algorithms, as
well as a possibility to use a different implementation of MGF.


Intel® Cryptography Primitives Library implementation of MGFs limits the length (in octets) of an
input message for any specific MGF by the range of the int data type,
with the upper bound of 2\ :sup:`32`-1.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   The crypto community does not consider SHA-1 or MD5 algorithms secure
   anymore.


   Recommendation: use a more secure hash algorithm (for example, any
   algorithm from the SHA-2 family) instead of SHA-1 or MD5.

.. toctree::
   :maxdepth: 1


   users-implementation-of-a-mask-generation-function
   mgf
   mgf1_rmf-mgf2_rmf