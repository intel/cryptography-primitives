.. _mbx_sm2_ecdsa_verify:


mbx_sm2_ecdsa_verify
====================


Verifies the SM2 ECDSA signature.


Syntax
------


mbx_status mbx_sm2_ecdsa_verify_mb8(const int8u\* constpa_sign_r[8],
const int8u\* constpa_sign_s[8], const int8u\* constpa_user_id[8], const
int user_id_len[8], const int8u\* constpa_msg[8], const int msg_len[8],
const int64u\* constpa_pubx[8], const int64u\* constpa_puby[8], const
int64u\* const pa_pubz[8], int8u\*pBuffer);


mbx_status mbx_sm2_ecdsa_verify_ssl_mb8(const ECDSA_SIG\*
constpa_sig[8], const int8u\* constpa_user_id[8], const int
user_id_len[8], const int8u\* constpa_msg[8], const int msg_len[8],
const BIGNUM\* constpa_pubx[8], const BIGNUM\* constpa_puby[8], const
BIGNUM\* const pa_pubz[8], int8u\*pBuffer);


Include Files
-------------


``crypto_mb/ec_sm2.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_sign_r   
     -  Array of pointers to the r-components of the signature.
   * -     pa_sign_s   
     -  Array of pointers to the s-components of the signature.
   * -     pa_user_id   
     -  Array of pointers to the users ID.
   * -     user_id_len   
     -  Array of users ID length.
   * -     pa_msg   
     -  Array of pointers to the messages are being signed.
   * -     msg_len   
     -  Array of messages length.
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


The function computes user ids, messages, and signer public keys
representative using SM2 hash algorithm. User ids are specified by
pa_user_id parameter and its length are specified by user_id_len
parameter. Messages are specified by pa_msg parameter and its length are
specified by msg_len parameter. Public keys are specified by pa_pubx,
pa_puby, and pa_pubz parameters. If the pa_pubz parameter is not
``NULL``, then it is assumed that signer's public keys are represented
in projective coordinates. If the pa_pubz parameter is ``NULL``, then
signer's public keys are considered in affine coordinates.


Then function verifies digital signatures of the computed input data
representative. Signatures are represented as big endian byte strings
and r- and s- components are stored separately in pa_sign_r and
pa_sign_s parameters.


The work buffer specified by pBuffer parameter is not currently used and
can be ``NULL`` .


.. note::


   The function above has own "twin" with "_ssl" in the name. The
   differences in comparison with mbx_sm2_ecdsa_verify() are the
   following:


   -  


      .. container::
         :name: LI_6AF7B6FF9C4944CEBD30DB9BAB808CF0


         Representation of the key stuff. mbx_sm2_ecdsa_verify_ssl()
         functions use BIGNUM datatype instead of vector.


   -  


      .. container::
         :name: LI_360C2F65DAC349D2B155163BC1A9F971


         Representation of the signatures. mbx_sm2_ecdsa_verify_ssl()
         functions use ECDSA_SIG structure instead of vectors of ``r-``
         and ``s-`` components of the signature.


Return Values
-------------


The mbx_sm2_ecdsa_verify() functions return the status that indicates
whether the operation completed successfully or not. The status value of
0 indicates that all digital signatures were successfully verified. The
error condition can be analyzed by the MBX_GET_STS() call.

