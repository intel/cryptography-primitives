.. _mbx_sm2_ecpublic_key:


mbx_sm2_ecpublic_key
====================


Computes a public key.


Syntax
------


mbx_status mbx_sm2_ecpublic_key_mb8(int64u\* pa_pubx[8], int64u\*
pa_puby[8], int64u\* pa_pubz[8], const int64u\* const pa_skey[8],
int8u\* pBuffer);


mbx_status mbx_sm2_ecpublic_key_ssl_mb8(BIGNUM\* pa_pubx[8], BIGNUM\*
pa_puby[8], BIGNUM\* pa_pubz[8], const BIGNUM\* const pa_skey[8],
int8u\* pBuffer);


Include Files
-------------


``crypto_mb/ec_sm2.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -      pa_pubx   
     -  Array of pointers to the vectors of computed public key x-coordinates.
   * -      pa_puby   
     -  Array of pointers to the vectors of computed public key y-coordinates.
   * -      pa_pubz   
     -  Array of pointers to the vectors of computed public key z-coordinates.
   * -      pa_skey   
     -  Array of pointers to the vectors of private keys.
   * -      pBuffer   
     -  Pointer to the work buffer.




Description
-----------


The function computes public keys using private keys specified by the
pa_skey parameter. If z-coordinate of computed public is required
(pa_pubz is not ``NULL``), then computed public keys are stored using
projective coordinates. If pa_pubz is ``NULL``, then computed public
keys are stored using affine coordinates.


The work buffer specified by the pBuffer parameteris not currently used
and can be ``NULL``.


.. note::


   The function above has own "twin" with "_ssl" in the name. The only
   difference in comparison with mbx_sm2_ecpublic_key() is
   representation of the parameters. mbx_sm2_ecpublic_key_ssl()
   functions use BIGNUM datatype instead of vector.


Return Values
-------------


The mbx_sm2_ecpublic_key() function returns the status that indicates
whether the operation completed successfully or not. The status value of
0 indicates that all operations completed successfully. The error
condition can be analyzed by the MBX_GET_STS() call.

