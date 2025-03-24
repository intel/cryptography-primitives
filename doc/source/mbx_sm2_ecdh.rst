.. _mbx_sm2_ecdh:

mbx_sm2_ecdh
============


Computes a shared secret.


Syntax
------


mbx_status mbx_sm2_ecdh_mb8(int8u\* pa_shared_key[8], const int64u\*
const pa_skey[8], const int64u\* const pa_pubx[8], const int64u\* const
pa_puby[8], const int64u\* const pa_pubz[8], int8u\* pBuffer);


mbx_status mbx_sm2_ecdh_ssl_mb8(int8u\* pa_shared_key[8], const BIGNUM\*
const pa_skey[8], const BIGNUM\* const pa_pubx[8], const BIGNUM\* const
pa_puby[8], const BIGNUM\* const pa_pubz[8], int8u\* pBuffer);


Include Files
-------------


``crypto_mb/ec_sm2.h``


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


The function computes a shared secret value using own private keys
specified by the pa_skey parameter and the party's public key specified
by pa_pubx, pa_puby, and pa_pubz parameters. If the pa_pubz parameter is
not ``NULL``, then it is assumed that party's public keys are
represented in projective coordinates. If the pa_pubz parameter is
``NULL``, then party's public keys are considered in affine coordinates.


The work buffer specified by the pBuffer parameteris not currently used
and can be ``NULL``.


.. note::


   The function above has own "twin" with "_ssl" in the name. The only
   difference in comparison with mbx_sm2_ecdh() is representation of the
   parameters. mbx_sm2_ecdh_ssl() functions use BIGNUM datatype instead
   of vector.


Return Values
-------------


The mbx_sm2_ecdh function returns the status that indicates whether the
operation completed successfully or not. The status value of 0 indicates
that all operations completed successfully. The error condition can be
analyzed by the MBX_GET_STS() call.

