.. _multi-buffer-cryptography-functions:


Multi-buffer Cryptography Functions
===================================


Introduction
------------


Crypto_mb library implements well known cryptography algorithms. The
feature of Crypto_mb is application of the usual cryptography algorithm
to different independent data in parallel.


For example, instead of usual (scalar) RSA decryption
``x = y``\ :sup:`d`\ ``mod n``, Crpto_mb consider vector
operation\ ``x[i] = y[i]``\ :sup:`d[i]`\ ``mod n[i]``, ``0<=i<8``, where
all eight operations run simultaneously. The single limitation is the
requirement that all the data must be compatible in terms of size. Thus,
RSAs moduli ``n[i]`` must be the same size, as well as ciphertext
``y[i]`` and recovered text ``x[i]``.


Together with new integer AVX512 instructions, this approach provides
performance benefit in comparison with scalar approach. This feature of
the Crypto_mb affects server and cloud applications positively.


Currently Crypto_mb supports:


-  RSA encryption and decryption of 1, 2 3 and 4Kb
-  ECDSA and ECDH/DHE over NIST recommended Elliptic Curves P256, P384
   and P521
-  ECDH/DHE over Curve25519


APIs, Parameters and Data Representation
----------------------------------------


Public APIs use parameters that are directly present in the math
description of algorithm, avoiding aggregated data structures. Usually,
parameters of public APIs are "arrays of pointers to data vectors".


Input and output data is represented as a big endian byte string (i.e.
leftmost byte is the most significant and rightmost byte is less
significant) of suitable length. The exception is X25519 functional,
where a private key is represented as a little endian byte string.


Usually, key stuff (public and private key components) are
multi-precision positive integers represented in the memory as a vector
of digits in base ``B (B = 2``\ :sup:`64`\ ``)``. Thus, ``L``-digit
non-negative integer value ``x`` in base ``B`` is represented as
follows:


``x = x[0]*B``\ :sup:`0`\ ``+ x[1]*B``\ :sup:`1`\ ``+ … + x[L-1]*B``\ :sup:`(L-1)`.


In case of OpenSSL-like APIs, the parameters, where it is applicable,
are represented by BIGNUM datatype as is customary in OpenSSL.


Return value
------------


APIs return 32-bit group status, allowing to parse each of eight
components connected with particular processed dataset. The function
``mbx_status MBX_GET_STS(mbx_status status, int numb)`` extracts from
the group status specified by the status parameter and returns the
status value corresponding to the processed dataset specified by the
numb parameter. Return value is one of the following:


-  ``MBX_STATUS_OK`` - operation competed successfully
-  ``MBX_STATUS_MISMATCH_PARAM_ERR`` - operation detected any
   incompatibility in parameters
-  ``MBX_STATUS_NULL_PARAM_ERR`` - operation detected NULL pointer
-  ``MBX_STATUS_LOW_ORDER_ERR`` - computed shared secret is zero
-  ``MBX_STATUS_SIGNATURE_ERR`` - r- or s- component of generated
   signature is zero

.. toctree::
   :maxdepth: 1

   
   rsa-algorithm-functions-mbx
   nist-recommended-elliptic-curve-functions
   montgomery-curve25519-elliptic-curve-functions
   edwards-curve25519-elliptic-curve-functions
   sm2-elliptic-curve-functions
   sm3-hash-functions
   sm4-algorithm-functions
   sm4_xts_algorithm_functions
   sm4_ccm_algorithm_functions
   sm4_gsm_algorithm_functions
   modular-exponentiation