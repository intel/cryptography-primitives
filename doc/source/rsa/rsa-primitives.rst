.. _rsa-primitives:



RSA Primitives
==============


The functions described in this section refer to RSA primitives.


The application code for conducting a typical RSA encryption must
perform the following sequence of operations, starting with building of
a crypto system:


#. Call the function
   :ref:`RSA_GetSizePublicKey <rsa_getsizepublickey-privatekeytype1-type2>`
   to get the size required to configure IppsRSAPublicKeyState context.
#. Ensure that the required memory space is properly allocated. With the
   allocated memory, call the
   :ref:`RSA_InitPublicKey <rsa_initpublickey-privatekeytype1-type2>`
   function to initialize the context.
#. Call
   :ref:`RSA_SetPublicKey <rsa_setpublickey-privatekeytype1-type2>`
   to set up RSA public key (*n*, *e*).
#. Call the
   :ref:`RSA_GetBufferSizePublicKey <rsa_getbuffersizepublickey-privatekey>`
   function to get the size of a temporary buffer.
#. Invoke the
   :ref:`RSA_Encrypt <rsa_encrypt>`
   function with the established RSA public key to encode the plaintext
   into the respective ciphertext.
#. Clean up secret data stored in the context.
#. Free the memory allocated for the IppsRSAPublicKeyState context by
   calling the operating system memory free service function.


The typical application code for the RSA decryption must perform the
following sequence of operations:


#. Call the function :ref:`GetSizePrivateKeyType1 or
   RSA_GetSizePrivateKeyType2 <rsa_getsizepublickey-privatekeytype1-type2>`
   to get the size required to configure IppsRSAPrivateKeyState context.
#. Ensure that the required memory space is properly allocated. With the
   allocated memory, call the :ref:`InitPrivateKeyType1 or
   RSA_InitPrivateKeyType2 <rsa_initpublickey-privatekeytype1-type2>`
   function to initialize the context.
#. Call the
   :ref:`RSA_GetBufferSizePrivateKey <rsa_getbuffersizepublickey-privatekey>`
   function to get the size of a temporary buffer.
#. Establish the RSA private key by means of either the
   :ref:`RSA_GenerateKeys <rsa_generatekeys>`
   function or by the key setup function :ref:`RSA_SetPrivateKeyType1 or
   RSA_SetPrivateKeyType2 <rsa_setpublickey-privatekeytype1-type2>`.
   The RSA_GenerateKeys function can generate both type 1 and type 2
   private keys, while the choice of the key setup function depends on
   the representation of the private key you are using.
#. Invoke the
   :ref:`RSA_Decrypt <rsa_decrypt>`
   function with the established RSA public key to decode the ciphertext
   into the respective plaintext.
#. Clean up secret data stored in the context.
#. Free the memory allocated for the IppsRSAPrivateKeyState context by
   calling the operating system memory free service function.


You can perform up to 8 encryption/decryption operations at once using
the :ref:`RSA_MB_Encrypt <rsa_mb_encrypt>`
and :ref:`RSA_MB_Decrypt <rsa_mb_decrypt>`
functions. For this, repeat steps 2-4 to set up the required number of
keys, and then repeat steps 6-7 for each initialized context.



.. rubric:: Related Information

:ref:`data-security-considerations`


.. toctree::
   :maxdepth: 1


   rsa_encrypt
   rsa_mb_encrypt
   rsa_decrypt
   rsa_mb_decrypt
   example-of-using-rsa-primitive-functions
