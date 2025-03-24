.. _mbx_rsa_private:

mbx_rsa_private
===============


Performs the private key RSA decryption operation.


Syntax
------


mbx_status mbx_rsa_private_mb8(const int8u\* const from_pa[8], int8u\*
const to_pa[8], const int64u\* const d_pa[8], const int64u\* const
n_pa[8], int rsaBitlen, const mbx_RSA_Method\* m, int8u\* pBuffer);


mbx_status mbx_rsa_private_ssl_mb8(const int8u\* const from_pa[8],
int8u\* const to_pa[8], const BIGNUM\* const d_pa[8], const BIGNUM\*
const n_pa[8], int rsaBitlen);


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
   * -      d_pa   
     -  Array of pointers to the RSAs private exponent vectors.
   * -      n_pa   
     -  Array of pointers to the RSAs modulus vectors.
   * -      rsaBitLen   
     -  Size of RSAs moduli in bits.
   * -      m   
     -  Pointer to the pre-defined data structure specified by the RSA encryption operation.
   * -      pBuffer   
     -  Pointer to the work buffer.




Description
-----------


The mbx_rsa_private() function performs independent RSA private key
operations using RSA private key in form of a pair - private exponent
(``d``) and modulus (``n``). The exponents are passed through d_pa and
moduli are passed though n_pa parameters. The size of RSAs moduli and
private exponents must be the same and equal to rsaBitlen bits. The
function decrypts ciphertexts specified by the from_pa parameter in
parallel, and stores recovered ciphertexts in the memory locations
specified by the to_pa parameter. Memory buffers of the plain- and
ciphertext must be ceil(rsaBitlen/8) bytes length.


At the moment, RSA-10024, RSA-2048, RSA-3072and RSA-4096 are supported
only. If ``m`` is ``NULL``, the functionuses
mbx_RSA_private_Method(rsaBitsize). If ``m`` is not ``NULL``, it must be
assigned toeither mbx_RSA1K\_ private_Method(), mbx_RSA2K\_
private_Method(), mbx_RSA3K\_ private_Method() or mbx_RSA4K\_
private_Method() and match to rsaBitlen value.


If pBuffer is ``NULL``, then the function allocated a work buffer of
suitable size dynamically. Anallocated buffer will be released before
the function return. If the workbuffer is allocated in the application,
it affects performancepositively. Thembx_RSA_Method_BufSize() function
returns the size of the work buffer requiredfor the operation.


The function itself does not support any kind of padding. The
application is responsible for the padding if it is required.


.. note::


   The mbx_rsa_private_ssl() function is the "twin" of mbx_rsa_private()
   one. Itacts the same. The basic difference in comparison
   withmbx_rsa_private() is the representation of RSA key stuff.
   mbx_rsa_private_ssl uses BIGNUM datatype insteadof vector.


Return Values
-------------


The mbx_rsa_private() function returns the status that indicates whether
the operation completed successfully or not. The status value of 0
indicates that all operations completed successfully. The error
condition can be analyzed by the MBX_GET_STS() call.



.. rubric:: Related Information

:ref:`mbx_rsa_method_bufsize`
