.. _functions-based-on-gf-p:

Functions Based on GF(*p*)
==========================


This section describes functions designed to specify the elliptic curve
cryptosystem and perform various operations on the elliptic curve
defined over a prime finite field. The examples of the operations are
shown below:


- Setting up operations:
  :ref:`GFpECSet <gfpecset>`
  sets up elliptic curve domain parameters.
- Computation operations:
  :ref:`GFpECAddPoint <gfpecaddpoint>`
  computes the sum of two points on an elliptic curve.
  :ref:`GFpECMulPoint <gfpecmulpoint>`
  performs the scalar multiplication of a point on the elliptic curve.
  :ref:`GFpECSignDSA <gfpecpsigndsa-gfpecpsignnr-gfpecpsignsm2>`
  computes the digital signature of a message.
- Validation operations:
  :ref:`GFpECVerify <gfpecverify>`
  checks validity of the elliptic curve domain parameters.
  :ref:`GFpECTstKeyPair <gfpectstkeypair>`
  validates correctness of the public and private keys.
- Generation operations:
  :ref:`GFpECPrivateKey, GFpECPublicKey <gfpecprivatekey-gfpecpublickey-gfpectstkeypair>`
  generates a private key and computes a public key for the given
  elliptic cryptosystem.
- Retrieval operations:
  :ref:`GFpECGet <gfpecget>`
  retrieves elliptic curve domain parameters.
  :ref:`GFpECGetSubgroup <gfpecgetsubgroup>`
  retrieves the size of a base point in bytes.


All functions described in this section employ a context IppsGFpState
that catches several auxiliary components specifying operations
performed on the elliptic curve or entire elliptic cryptosystem. ECCP
stands for Elliptic Curve Cryptography Prime and means that all
functions whose name include this abbreviation perform operations over a
prime finite field GF( *p*).

.. note::


   .. rubric:: Important
      :class: NoteTipHead

   To provide minimum security of the elliptic curve cryptosystem over a
   prime finite field, the length of the underlying prime must be equal
   to or greater than 160 bits.