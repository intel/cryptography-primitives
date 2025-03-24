.. _mbx_rsa_private_crt:

mbx_rsa_private_crt
===================


Performs the private key RSA decryption operation.


Syntax
------


mbx_status mbx_rsa_private_crt_mb8(const int8u\* const from_pa[8],
int8u\* const to_pa[8], const int64u\* const p_pa[8], const int64u\*
const q_pa[8], const int64u\* const dp_pa[8], const int64u\* const
dq_pa[8], const int64u\* const iq_pa[8], int rsaBitlen, const
mbx_RSA_Method\* m, int8u\* pBuffer);


mbx_status mbx_rsa_private_crt_ssl_mb8(const int8u\* const from_pa[8],
int8u\* const to_pa[8], const BIGNUM\* const p_pa[8], const BIGNUM\*
const q_pa[8], const BIGNUM\* const dp_pa[8], const BIGNUM\* const
dq_pa[8], const BIGNUM\* const iq_pa[8], int rsaBitlen);


Include Files
-------------


``crypto_mb/rsa.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -      from_pa   
     -  Array of pointers to the ciphertext data vectors.
   * -      to_pa   
     -  Array of pointers to the recovered data vectors.
   * -      p_pa   
     -  Array of pointers to the p-prime factor vectors of RSA moduli.
   * -      q_pa   
     -  Array of pointers to the q-prime factor vectors of RSA moduli.
   * -      dp_pa   
     -  Array of pointers to the p's CRT private exponent vectors.
   * -      dq_pa   
     -  Array of pointers to the q's CRT private exponent vectors.
   * -      iq_pa   
     -  Array of pointers to CRT coefficient (multiplicative inversion of q with respect to p) vectors.
   * -      rsaBitLen   
     -  Size of RSAs moduli in bits.
   * -      m   
     -  Pointer to the pre-defined data structure specified by the RSA encryption operation.
   * -      pBuffer   
     -  Pointer to the work buffer.




Description
-----------


The mbx_rsa_private_crt() function performs independent CRT-based RSA
private key operations using RSAprivate key in a quintuple form -
private factors (``p`` and ``q``), privateexponents (``dp`` and ``dq``)
and CRT coefficient ``invq``. The factors are passed through p_pa and
q_pa, exponents are passed though dp_pa and dq_pa and CRT coefficients
are passed through iq_pa parameter. The size of RSAs factors, private
exponents and CRT coefficients must be the same and equal to rsaBitlen/2
bits. The function decrypts ciphertexts specified by the from_pa
parameter in parallel, and stores recovered ciphertexts in the memory
locations specified by the to_pa parameter. Memory buffers of the plain-
and ciphertext must be ceil(rsaBitlen/8) bytes length.


At the moment, RSA-10024, RSA-2048, RSA-3072and RSA-4096 are supported
only. If ``m`` is ``NULL``, the functionuses
mbx_RSA_private_crt_Method(rsaBitsize). If ``m`` is not ``NULL``, it
must be assigned toeither mbx_RSA1K\_ private_crt_Method(), mbx_RSA2K\_
private_crt_Method(), mbx_RSA3K\_ private_crt_Method() or mbx_RSA4K\_
private_crt_Method() and match to rsaBitlen value.


If pBuffer is ``NULL``, then the function allocated a work buffer of
suitable size dynamically. Anallocated buffer will be released before
the function return. If the workbuffer is allocated in the application,
it affects performancepositively. Thembx_RSA_Method_BufSize() function
returns the size of the work buffer requiredfor the operation.


The function itself does not support any kind of padding. The
application is responsible for the padding if it is required.


.. note::


   The mbx_rsa_private_crt_ssl() function is the "twin" of
   mbx_rsa_private_crt() one. Itacts the same. The basic difference in
   comparison withmbx_rsa_private() is the representation of RSA key
   stuff. mbx_rsa_private_crt_ssl uses BIGNUM datatype insteadof vector.


Return Values
-------------


The mbx_rsa_private_crt() function returns the status that indicates
whether the operation completed successfully or not. The status value of
0 indicates that all operations completed successfully. The error
condition can be analyzed by the MBX_GET_STS() call.

