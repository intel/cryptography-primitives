.. _mbx_ed25519_public_key_mb8:


mbx_ed25519_public_key_mb8
==========================


Computes a public key.


Syntax
------


mbx_status mbx_ed25519_public_key_mb8(ed25519_public_key\*
pa_public_key[8], const ed25519_private_key\* const pa_private_key[8]);


Include Files
-------------


``crypto_mb/ed25519.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_public_key   
     -  Array of pointers to the public keys of 32 bytes length each.
   * -      pa_private_key   
     -  Array of pointers to the private keys of 32 bytes length each.




Description
-----------


The mbx_ed25519_public_key_mb8 function computes public keys pointed by
pa_public_key parameter using input private keys pointed by the
pa_private_key parameter. Private key is represented as 32-bytes length
string that is kept in secret. The length of each computed public key is
32 bytes too.


Return Values
-------------


The mbx\_ ed25519_public_key_mb8 function returns the status that
indicates whether the operation completed successfully or not. The
status value of 0 indicates that all operations completed successfully.
The error condition can be analyzed by the MBX_GET_STS() call. The
result of verification is returned as status too. The MBX_STATUS_OK
value means that signature is verified, else status contains
MBX_STATUS_SIGNATURE_ERR value.

