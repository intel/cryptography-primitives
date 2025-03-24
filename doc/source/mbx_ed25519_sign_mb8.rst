.. _mbx_ed25519_sign_mb8:

mbx_ed25519_sign_mb8
====================


Computes signature.


Syntax
------


mbx_status mbx_ed25519_sign_mb8(ed25519_sign_component\* pa_sign_r[8],
ed25519_sign_component\* pa_sign_s[8], const int8u\* const pa_msg[8],
const int32u msgLen[8], const ed25519_private_key\* const
pa_private_key[8], const ed25519_public_key\* const pa_public_key[8]);


Include Files
-------------


``crypto_mb/ed25519.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_sign_r   
     -  Array of pointers to the signature's r- components of 32 bytes length each.
   * -     pa_sign_s   
     -  Array of pointers to the signature's s- components of 32 bytes length each.
   * -     pa_msg   
     -  Array of pointers to the messages.
   * -     msgLen   
     -  Array of the message's lengths above in bytes.
   * -     pa_public_key   
     -  Array of pointers to the public keys of 32 bytes length each.
   * -      pa_private_key   
     -  Array of pointers to the private keys of 32 bytes length each.




Description
-----------


The mbx_ed25519_sign_mb8 function computes r- and s- signature
components, each of which corresponds to the message specified by
pa_msg[i] parameter of msgLen[i] length. The pair {private, public} keys
specified by pa_private_key[i] and pa_public_key[i] parameters.


.. note::


   mbx_ed25519_sign_mb8 is implementing so called PureEDDSA variant of
   EdDSA. For more information, see RFC 8032.


Return Values
-------------


The mbx\_ ed25519_public_key_mb8 function returns the status that
indicates whether the operation completed successfully or not. The
status value of 0 indicates that all operations completed successfully.
The error condition can be analyzed by the MBX_GET_STS() call. The
result of verification is returned as status too. The MBX_STATUS_OK
value means that signature is verified, else status contains
MBX_STATUS_SIGNATURE_ERR value.

