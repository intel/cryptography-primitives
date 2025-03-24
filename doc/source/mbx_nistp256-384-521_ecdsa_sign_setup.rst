.. _mbx_nistp256-384-521_ecdsa_sign_setup:


mbx_nistp256/384/521_ecdsa_sign_setup
=====================================


Precomputes the ECDSA signature.


Syntax
------


mbx_status mbx_nistp256_ecdsa_sign_setup_mb8(int64u\*
pa_inv_eph_skey[8], int64u\* pa_sign_rp[8], const int64u\* const
pa_eph_skey[8], int8u\* pBuffer);


mbx_status mbx_nistp256_ecdsa_sign_setup_ssl_mb8(BIGNUM\*
pa_inv_eph_skey[8], BIGNUM\* pa_sign_rp[8], const BIGNUM\* const
pa_eph_skey[8], int8u\* pBuffer);


mbx_status mbx_nistp384_ecdsa_sign_setup_mb8(int64u\*
pa_inv_eph_skey[8], int64u\* pa_sign_rp[8], const int64u\* const
pa_eph_skey[8], int8u\* pBuffer);


mbx_status mbx_nistp384_ecdsa_sign_setup_ssl_mb8(BIGNUM\*
pa_inv_eph_skey[8], BIGNUM\* pa_sign_rp[8], const BIGNUM\* const
pa_eph_skey[8], int8u\* pBuffer);


mbx_status mbx_nistp521_ecdsa_sign_setup_mb8(int64u\*
pa_inv_eph_skey[8], int64u\* pa_sign_rp[8], const int64u\* const
pa_eph_skey[8], int8u\* pBuffer);


mbx_status mbx_nistp521_ecdsa_sign_setup_ssl_mb8(BIGNUM\*
pa_inv_eph_skey[8], BIGNUM\* pa_sign_rp[8], const BIGNUM\* const
pa_eph_skey[8], int8u\* pBuffer);


Include Files
-------------


``crypto_mb/ec_nistp256.h```


``crypto_mb/ec_nistp384.h``


``crypto_mb/ec_nistp512.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -      pa_eph_skey   
     -  Array of pointers to the ephemeral private key vectors.
   * -      pa_inv_eph_skey   
     -  Array of pointers to the vectors of ephemeral private key inversion.
   * -      pa_sign_rp   
     -  Array of pointers to the vectors of pre-computed r-component signatures.
   * -      pBuffer   
     -  Pointer to the work buffer.




Description
-----------


Each function targets at the elliptic curve (EC) specified in thename
(nistp256, nistp384 or nistp521). This function may be used toprecompute
a part of the signature operation. Based on ephemeralprivate keys,
specified by pa_eph_skey parameter the functionprecomputes:


-  r-component of the signature storing the result specified by
   pa_sign_rp (step 2 of ECDSAoperation)


-  multiplicative inversion of ephemeral privatekey (used in step 3 of
   ECDSA operation) storing the result asspecified by pa_inv_eph_skey
   parameter


Precomputed can be used later in suitable
mbx_nistp_ecdsa_sign_complete_mb8()function.


The work buffer specified by pBuffer parameteris not currently used and
can be ``NULL``.


.. note::


   All the functions above have own "twins" with "_ssl" in the name. The
   "twin" associated with the EC acts the same. The single difference in
   comparison with mbx_nistp256/384/521_ecdsa_sign_setup() is
   representation of the parameters.
   mbx_nistp256/384/521_ecdsa_sign_setup_ssl() functions use BIGNUM
   datatype instead of vector.


Return Values
-------------


The mbx_nistp256/384/521_ecdsa_setup functions return the status that
indicates whether the operation completed successfully or not. The
status value of 0 indicates that all operations completed successfully.
The error condition can be analyzed by the MBX_GET_STS() call.

