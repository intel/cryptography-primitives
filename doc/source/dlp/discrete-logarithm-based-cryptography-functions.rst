.. _discrete-logarithm-based-cryptography-functions:


Discrete-Logarithm-Based Cryptography Functions
===============================================


This section introduces Intel® Cryptography Primitives Library
functions allowing for different operations with
Discrete Logarithm (DL) based cryptosystem over a prime finite field
GF(*p*). The functions are mainly based on the :term:`IEEE P1363A <[IEEE P1363A]>`
standard. Implementation of the Digital Signature operations is based on
:term:`FIPS PUB 186-2 <[FIPS PUB 186-2]>`.
The Diffie-Hellman (DH) Agreement scheme is based on
:term:`X9.42 <[X9.42]>`.


All functions described in this section employ the IppsDLPState context
as operational vehicle that carries domain parameters of the DL
cryptosystem, a pair of keys, and working buffers.


The application code intended for executing typical operations should
perform the following sequence of operations:


#. Call the function
   :ref:`DLPGetSize <dlpgetsize>`
   to get the size required to configure the IppsDLPState context.
#. Ensure that the required memory space is properly allocated. With the
   allocated memory, call the
   :ref:`DLPInit <dlpinit>`
   function to initialize the context of the DL-based cryptosystem.
#. Set domain parameters of the DL-based cryptosystem by calling the
   :ref:`DLPSet <dlpset>`
   function, or generate domain parameters by calling the
   :ref:`DLPGenerateDSA <dlpgeneratedsa>`
   or
   :ref:`DLPGenerateDH <dlpgeneratedh>`.
#. Call one of the functions
   :ref:`DLPSignDSA <dlpsigndsa>`,
   :ref:`DLPVerifyDSA <dlpverifydsa>`,
   and
   :ref:`DLPSharedSecretDH <dlpsharedsecretdh>`
   to compute digital signature, to verify authenticity of the digital
   signature, and to compute the shared element accordingly.
#. Clean up secret data stored in the context.
#. Free the memory allocated for the IppsDLPState context by calling the
   operating system memory free service function unless the context is
   no longer needed.


The IppsDLPState context is position-dependent. The
:ref:`DLPPack/DLPUnpack <dlppack-dlpunpack>`
functions transform the position-dependent context to a
position-independent form and vice versa.


.. rubric:: Related Information

:ref:`data-security-considerations`


.. toctree::
   :maxdepth: 1


   dlpgetsize
   dlpinit
   dlppack-dlpunpack
   dlpset
   dlpget
   dlpsetdp
   dlpgetdp
   dlpgenkeypair
   dlppublickey
   dlpvalidatekeypair
   dlpsetkeypair
   dlpgeneratedsa
   dlpvalidatedsa
   dlpsigndsa
   dlpverifydsa
   example-discrete-logarithm-primitive-functions
   dlpgeneratedh
   dlpvalidatedh
   dlpsharedsecretdh
   dlgetresultstring
