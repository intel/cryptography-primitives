.. _ml-dsa-index:

ML-DSA
======

The **Module-Lattice-Based Digital Signature Algorithm (ML-DSA)** is a set of
algorithms that can be used to generate and verify digital signatures. ML-DSA
is designed to be secure even against adversaries in possession of a
large-scale quantum computer.

The implementation is based on the
`FIPS 204 standard <https://csrc.nist.gov/pubs/fips/204/final>`__
and provides three main primitives:

-  Key Generation
-  Signing
-  Verification

Using a product containing these algorithms does not guarantee the security
of the overall system in which the product is used.
The security of the system depends on the secure use of the product in the
overall system, including proper key management.

The signature generation implementation does not incorporate
additional constant-time techniques. It performs honest acceptance-rejection
sampling as specified in the FIPS 204 standard to achieve optimal performance.

.. note::

   .. rubric:: API usage
      :class: NoteTipHead

   The API family is supported in experimental mode. To use the functions, users need to define
   the ``IPPCP_PREVIEW_ML_DSA`` macro before including the ``ippcp.h`` header file. See
   :ref:`Preview Features <experimental>` for more details.

.. _ml-dsa-params:

Supported ML-DSA Parameter Sets
--------------------------------

.. code:: cpp

    typedef enum {
        ML_DSA_44 = 1,
        ML_DSA_65 = 2,
        ML_DSA_87 = 3
    } IppsMLDSAParamSet;

Example: Key Generation, Signing, and Verification
---------------------------------------------------

.. literalinclude:: ../../../examples/post-quantum/ml_dsa_87_keygen_sign_verify.cpp
    :language: cpp

Related Functionality
---------------------

.. toctree::
   :maxdepth: 1

   get-size
   get-info
   init
   buffers-get-size
   key-gen
   sign
   verify
