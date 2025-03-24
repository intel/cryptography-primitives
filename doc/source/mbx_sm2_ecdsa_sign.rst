.. _mbx_sm2_ecdsa_sign:

mbx_sm2_ecdsa_sign
==================


Generates the SM2 ECDSA signature.


Syntax
------


mbx_status mbx_sm2_ecdsa_sign_mb8(int8u\* pa_sign_r[8], int8u\*
pa_sign_s[8], const int8u\* const pa_user_id[8], const int
user_id_len[8], const int8u\* const pa_msg[8], const int msg_len[8],
const int64u\* const pa_eph_skey[8], const int64u\* const
pa_reg_skey[8], const int64u\* const pa_pubx[8], const int64u\* const
pa_puby[8], const int64u\* const pa_pubz[8], int8u\* pBuffer);


mbx_status mbx_sm2_ecdsa_sign_ssl_mb8(int8u\* pa_sign_r[8], int8u\*
pa_sign_s[8], const int8u\* const pa_user_id[8], const int
user_id_len[8], const int8u\* const pa_msg[8], const int msg_len[8],
const BIGNUM\* const pa_eph_skey[8], const BIGNUM\* const
pa_reg_skey[8], const BIGNUM\* const pa_pubx[8], const BIGNUM\* const
pa_puby[8], const BIGNUM\* const pa_pubz[8], int8u\* pBuffer);


Include Files
-------------


``crypto_mb/ec_sm2.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -      pa_sign_r   
     -  Array of pointers to the resulting r-components of the signature.
   * -      pa_sign_s   
     -  Array of pointers to the resulting s-components of the signature.
   * -     pa_user_id   
     -     Array of pointers to the users ID.   
   * -     user_id_len   
     -      Array of users ID length.   
   * -      pa_msg   
     -  Array of pointers to the message representatives are being signed.
   * -     msg_len   
     -      Array of messages length.   
   * -      pa_eph_skey   
     -  Array of pointers to the signer's ephemeral private key.
   * -      pa_reg_skey   
     -  Array of pointers to the signer's regular private key.
   * -     pa_pubx   
     -      Array of pointers to the party's public keys X-coordinates   
   * -     pa_puby   
     -      Array of pointers to the party's public keys Y-coordinates   
   * -     pa_pubz   
     -      Array of pointers to the party's public keys Z-coordinates   
   * -      pBuffer   
     -  Pointer to the work buffer.




Description
-----------


The function computes user ids, messages, and signer public keys
representative using SM2 hash algorithm. User ids are specified by
pa_user_id parameter and its length are specified by user_id_len
parameter. Messages are specified by pa_msg parameter and its length are
specified by msg_len parameter. Public keys are specified by pa_pubx,
pa_puby, and pa_pubz parameters. If the pa_pubz parameter is not
``NULL``, then it is assumed that signer's public keys are represented
in projective coordinates. If the pa_pubz parameter is ``NULL``, then
signer's public keys are considered in affine coordinates.


Computed input data representative signed using regular and private keys
specified by pa_reg_skey and pa_eph_skey parameters correspondingly.
Computed signature converts r- and s- components of the signature into
big endian byte strings and stores them separately in locations
specified by pa_sign_r and pa_sign_s parameters.


The work buffer specified by the pBuffer parameteris not currently used
and can be ``NULL``.


.. note::


   The function above has own "twin" with "_ssl" in the name. The only
   difference in comparison with mbx_sm2_ecdsa_sign() is representation
   of the parameters. mbx_sm2_ecdsa_sign_ssl() functions use BIGNUM
   datatype instead of vector.


Return Values
-------------


The mbx_sm2_ecdsa_sign() functions return the status that indicates
whether the operation completed successfully or not. The status value of
0 indicates that all operations completed successfully. The error
condition can be analyzed by the MBX_GET_STS() call.

