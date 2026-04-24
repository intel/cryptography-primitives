.. _mbx_nistp256-384-521_ecdh:



mbx_nistp256/384/521_ecdh
=========================


Computes a shared secret.


Syntax
------


mbx_status mbx_nistp256_ecdh_mb8(int8u\* pa_shared_key[8], const
int64u\* const pa_skey[8], const int64u\* const pa_pubx[8], const
int64u\* const pa_puby[8], const int64u\* const pa_pubz[8], int8u\*
pBuffer);


mbx_status mbx_nistp256_ecdh_ssl_mb8(int8u\* pa_shared_key[8], const
BIGNUM\* const pa_skey[8], const BIGNUM\* const pa_pubx[8], const
BIGNUM\* const pa_puby[8], const BIGNUM\* const pa_pubz[8], int8u\*
pBuffer);


mbx_status mbx_nistp384_ecdh_mb8(int8u\* pa_shared_key[8], const
int64u\* const pa_skey[8], const int64u\* const pa_pubx[8], const
int64u\* const pa_puby[8], const int64u\* const pa_pubz[8], int8u\*
pBuffer);


mbx_status mbx_nistp384_ecdh_ssl_mb8(int8u\* pa_shared_key[8], const
BIGNUM\* const pa_skey[8], const BIGNUM\* const pa_pubx[8], const
BIGNUM\* const pa_puby[8], const BIGNUM\* const pa_pubz[8], int8u\*
pBuffer);


mbx_status mbx_nistp521_ecdh_mb8(int8u\* pa_shared_key[8], const
int64u\* const pa_skey[8], const int64u\* const pa_pubx[8], const
int64u\* const pa_puby[8], const int64u\* const pa_pubz[8], int8u\*
pBuffer);


mbx_status mbx_nistp521_ecdh_ssl_mb8(int8u\* pa_shared_key[8], const
BIGNUM\* const pa_skey[8], const BIGNUM\* const pa_pubx[8], const
BIGNUM\* const pa_puby[8], const BIGNUM\* const pa_pubz[8], int8u\*
pBuffer);


Include Files
-------------


``crypto_mb/ec_nistp256.h``


``crypto_mb/ec_nistp384.h``


``crypto_mb/ec_nistp521.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -      pa_shared_key   
     -  Array of pointers to the vectors of computed shared secret values.
   * -      pa_pubx   
     -  Array of pointers to the vectors of party's public key x-coordinates.
   * -      pa_puby   
     -  Array of pointers to the vectors of party's public key y-coordinates.
   * -      pa_pubz   
     -  Array of pointers to the vectors of party's public key z-coordinates
   * -      pa_skey   
     -  Array of pointers to the vectors of own private keys.
   * -      pBuffer   
     -  Pointer to the work buffer.




Description
-----------


Each function targets at the elliptic curve (EC) specified in thename
(nistp256, nistp384 or nistp521). The function computes a shared secret
value using own private keys specified by the pa_skey parameter and the
party's public key specified by pa_pubx, pa_puby and pa_pubz parameters.
If the pa_pubz parameter is not ``NULL``, then it is assumed that
party's public keys are represented in projective coordinates. If the
pa_pubz parameter is ``NULL``, then party's public keys are considered
in affine coordinates.


The work buffer specified by the pBuffer parameteris not currently used
and can be ``NULL``.


.. note::


   All the functions above have own "twins" with "_ssl" in the name. The
   "twin" associated with the EC acts the same. The single difference in
   comparison with mbx_nistp256/384/521_ecdh() is representation of the
   parameters. mbx_nistp256/384/521_ecdh_ssl() functions use BIGNUM
   datatype instead of vector.


Return Values
-------------


The mbx_nistp256/384/521_ecdh functions return the status that indicates
whether the operation completed successfully or not. The status value of
0 indicates that all operations completed successfully. The error
condition can be analyzed by the MBX_GET_STS() call.

