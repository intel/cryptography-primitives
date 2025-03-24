.. _mbx_nistp256-384-521_ecdsa_verify:


mbx_nistp256/384/521_ecdsa_verify
=================================


Verifies the ECDSA signature using the NIST recommended elliptic curves
over prime P256/P384/P521.


Syntax
------


mbx_status mbx_nistp256_ecdsa_verify_mb8(const int8u\*
constpa_sign_r[8], const int8u\* constpa_sign_s[8], const int8u\*
constpa_msg[8], const int64u\* constpa_pubx[8], const int64u\*
constpa_puby[8], const int64u\* constpa_pubz[8], int8u\*pBuffer);


mbx_status mbx_nistp256_ecdsa_verify_ssl_mb8(const ECDSA_SIG\*
constpa_sign[8], const int8u\* constpa_msg[8], const BIGNUM\*
constpa_pubx[8], const BIGNUM\* constpa_puby[8], const BIGNUM\*
constpa_pubz[8], int8u\*pBuffer);


mbx_status mbx_nistp384_ecdsa_verify_mb8(const int8u\*
constpa_sign_r[8], const int8u\* constpa_sign_s[8], const int8u\*
constpa_msg[8], const int64u\* constpa_pubx[8], const int64u\*
constpa_puby[8], const int64u\* constpa_pubz[8], int8u\*pBuffer);


mbx_status mbx_nistp384_ecdsa_verify_ssl_mb8(const ECDSA_SIG\*
constpa_sign[8], const int8u\* constpa_msg[8], const BIGNUM\*
constpa_pubx[8], const BIGNUM\* constpa_puby[8], const BIGNUM\*
constpa_pubz[8], int8u\*pBuffer);


mbx_status mbx_nistp521_ecdsa_verify_mb8(const int8u\*
constpa_sign_r[8], const int8u\* constpa_sign_s[8], const int8u\*
constpa_msg[8], const int64u\* constpa_pubx[8], const int64u\*
constpa_puby[8], const int64u\* constpa_pubz[8], int8u\*pBuffer);


mbx_status mbx_nistp521_ecdsa_verify_ssl_mb8(const ECDSA_SIG\*
constpa_sign[8], const int8u\* constpa_msg[8], const BIGNUM\*
constpa_pubx[8], const BIGNUM\* constpa_puby[8], const BIGNUM\*
constpa_pubz[8], int8u\*pBuffer);


Include Files
-------------


``crypto_mb/ec_nistp256.h``


``crypto_mb/ec_nistp384.h``


``crypto_mb/ec_nistp512.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_sign_r   
     -  Array of pointers to the r-components of the signature.
   * -     pa_sign_s   
     -  Array of pointers to the s-components of the signature.
   * -     pa_sign   
     -  Array of pointers to the ECDSA_SIG structures.
   * -     pa_msg   
     -  Array of pointers to the message representatives that have been signed.
   * -     pa_pubx   
     -  Array of pointers to the vectors of signer's public key x-coordinates.
   * -     pa_puby   
     -  Array of pointers to the vectors of signer's public key y-coordinates.
   * -     pa_pubz   
     -  Array of pointers to the vectors of signer's public key z-coordinates..
   * -     pBuffer   
     -  Pointer to the work buffer.




Description
-----------


Each function targets at the elliptic curve (EC) specified in the name (
nistp256 , nistp384 or nistp521 ). This function verifies digital
signatures of the message representatives passed by ps_msg parameter
using public keys specified by pa_pubx , pa_puby and pa_pubz parameters.
If the pa_pubz parameter is not ``NULL`` , then it is assumed that
signer's public keys are represented in projective coordinates. If the
pa_pubz parameter is ``NULL`` , then signer's public keys are considered
in affine coordinates.


The function assumes that the length of the message representative is
equal to the length of ``r`` (order of EC subgroup). Signatures are
represented as big endian byte strings and ``r-`` and ``s-`` components
are stored separately in pa_sign_r and pa_sign_s parameters.


The work buffer specified by pBuffer parameter is not currently used and
can be ``NULL`` .


.. note::


   All the functions above have own "twins" with "_ssl" in the name. The
   "twin" associated with the EC acts the same. The differences in
   comparison with mbx_nistp256/384/521_ecdsa_verify() are the
   following:


   -  Representation of the key stuff.
      mbx_nistp256/384/521_ecdsa_verify_ssl() functions use BIGNUM
      datatype instead of vector.


   -  Representation of the signatures.
      mbx_nistp256/384/521_ecdsa_verify_ssl() functions use ECDSA_SIG
      structure instead of vectors of ``r-`` and ``s-`` components of
      the signature.


Return Values
-------------


The mbx_nistp256/384/521_ecdsa_verify functions return the status that
indicates whether the operation completed successfully or not. The
status value of 0 indicates that all digital signatures were
successfully verified. The error condition can be analyzed by the
MBX_GET_STS() call.

