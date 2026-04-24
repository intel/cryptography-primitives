.. _mbx_x25519_public_key:


mbx_x25519_public_key
=====================


Computes a public key.


Syntax
------


mbx_status mbx_x25519_public_key_mb8(int8u\* const pa_public_key[8],
const int8u\* const pa_private_key[8]);


Include Files
-------------


``crypto_mb/x25519.h``


Parameters
----------


.. list-table:: 
   :header-rows: 0

   * -     pa_public_key   
     -  Array of pointers to the vectors of computed public key x-coordinates.
   * -      pa_private_key   
     -  Array of pointers to the vectors of private keys.




Description
-----------


This function computes x-coordinates only of pubic keys using private
keys specified by pa_private_key parameter. Any 256-bit vector is
applicable as a private key. Each vector must be at least 32-byte length
to store the computed x-coordinate of the public key.


Return Values
-------------


The ``mbx\_x25519_public_key`` function returns the status that indicates
whether the operation completed successfully or not. The status value of
0 indicates that all operations completed successfully. The error
condition can be analyzed by the ``MBX_GET_STS()`` call.

