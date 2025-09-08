.. _ml-kem-index:

ML-KEM
======

A **key-encapsulation mechanism (KEM)** is a set of algorithms that, under certain conditions,
can be used by two parties to establish a shared secret key over a public channel. A shared
secret key that is securely established using a KEM can then be used with symmetric-key
cryptographic algorithms to perform basic tasks in secure communications, such as encryption 
and authentication.

The implementation is based on `FIPS 203 standard <https://csrc.nist.gov/pubs/fips/203/final>`__
and provides 3 main primitives:

-  Key Generation
-  Encapsulation
-  Decapsulation

The security of ML-KEM is related to the computational difficulty of the *Module Learning with
Errors* problem.

.. note::

   .. rubric:: API usage
      :class: NoteTipHead

   The API family is supported in experimental mode. To use the functions, users need to define
   the ``IPPCP_PREVIEW_ML_KEM`` macro before including the ``ippcp.h`` header file. See
   :ref:`Preview Features <experimental>` for more details.

.. _ml-kem-params:

The supported ML-KEM parameter sets:
------------------------------------

.. code:: cpp

    typedef enum {
        IPPCP_ML_KEM_512  = 1,
        IPPCP_ML_KEM_768  = 2,
        IPPCP_ML_KEM_1024 = 3
    } IppsMLKEMParamSet;

Example. Key Generation, Encapsulation and Decapsulation
--------------------------------------------------------

.. literalinclude:: ../../../examples/post-quantum/ml_kem_512_keygen_encaps_decaps.cpp
    :language: cpp

Related functionality:
----------------------

.. toctree::
   :maxdepth: 1

   get-size
   get-info
   init
   buffers-get-size
   key-gen
   encaps
   decaps
