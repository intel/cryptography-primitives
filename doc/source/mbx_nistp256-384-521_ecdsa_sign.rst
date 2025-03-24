.. _mbx_nistp256-384-521_ecdsa_sign:


mbx_nistp256/384/521_ecdsa_sign
===============================


Generates the ECDSA signature using NIST recommended elliptic curves
over prime P256/P384/P521.


Syntax
------


mbx_status mbx_nistp256_ecdsa_sign_mb8(int8u\* pa_sign_r[8], int8u\*
pa_sign_s[8], const int8u\* const pa_msg[8], const int64u\* const
pa_eph_skey[8], const int64u\* const pa_reg_skey[8], int8u\*pBuffer);


mbx_status mbx_nistp256_ecdsa_sign_ssl_mb8(int8u\* pa_sign_r[8], int8u\*
pa_sign_s[8], const int8u\* const pa_msg[8], const BIGNUM\* const
pa_eph_skey[8], const BIGNUM\* const pa_reg_skey[8], int8u\*pBuffer);


mbx_status mbx_nistp384_ecdsa_sign_mb8(int8u\* pa_sign_r[8], int8u\*
pa_sign_s[8], const int8u\* const pa_msg[8], const int64u\* const
pa_eph_skey[8], const int64u\* const pa_reg_skey[8], int8u\*pBuffer);


mbx_status mbx_nistp384_ecdsa_sign_ssl_mb8(int8u\* pa_sign_r[8], int8u\*
pa_sign_s[8], const int8u\* const pa_msg[8], const BIGNUM\* const
pa_eph_skey[8], const BIGNUM\* const pa_reg_skey[8], int8u\*pBuffer);


mbx_status mbx_nistp521_ecdsa_sign_mb8(int8u\* pa_sign_r[8], int8u\*
pa_sign_s[8], const int8u\* const pa_msg[8], const int64u\* const
pa_eph_skey[8], const int64u\* const pa_reg_skey[8], int8u\*pBuffer);


mbx_status mbx_nistp521_ecdsa_sign_ssl_mb8(int8u\* pa_sign_r[8], int8u\*
pa_sign_s[8], const int8u\* const pa_msg[8], const BIGNUM\* const
pa_eph_skey[8], const BIGNUM\* const pa_reg_skey[8], int8u\*pBuffer);


Include Files
-------------


``crypto_mb/ec_nistp256.h``


``crypto_mb/ec_nistp384.h``


``crypto_mb/ec_nistp521.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -      pa_sign_r   
     -  Array of pointers to the resulting r-components of the signature.
   * -      pa_sign_s   
     -  Array of pointers to the resulting s-components of the signature.
   * -      pa_msg   
     -  Array of pointers to the message representatives are being signed.
   * -      pa_eph_skey   
     -  Array of pointers to the signer's ephemeral private key.
   * -      pa_reg_skey   
     -  Array of pointers to the signer's regular private key.
   * -      pBuffer   
     -  Pointer to the work buffer.




Description
-----------


Each function targets at the elliptic curve (EC) specified in thename
(nistp256, nistp384 or nistp521). The function computes digital
signature of the messagerepresentatives passed by the pa_msg parameter
using regular andprivate keys specified by pa_reg_skey and pa_eph_skey
parameterscorrespondingly. The function assumes that the length of
themessage representative is equal to length of ``r`` (order of
ECsubgroup). Computed signature (steps 1 - 3 of ECDSA
operation),converts ``r``- and ``s``- components of the signature into
big endian byte strings andstores them separately in locations specified
by pa_sign_r andpa_sign_s parameters.


The work buffer specified by the pBuffer parameteris not currently used
and can be ``NULL``.


.. note::


   All the functions above have own "twins" with "_ssl" in the name. The
   "twin" associated with the EC acts the same. The single difference in
   comparison with mbx_nistp256/384/521_ecdsa_sign() is representation
   of the parameters. mbx_nistp256/384/521_ecdsa_sign_ssl() functions
   use BIGNUM datatype instead of vector.


Return Values
-------------


The mbx_nistp256/384/521_ecdsa_sign functions return the status that
indicates whether the operation completed successfully or not. The
status value of 0 indicates that all operations completed successfully.
The error condition can be analyzed by the MBX_GET_STS() call.

