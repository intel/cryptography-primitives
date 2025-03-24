.. _functions-based-on-sm2:

Functions based on SM2
======================


Short Description


This section describes functions based on the SM2 encryption standard
for elliptic curves. For more information on the Elliptic Curve
Integrated Encryption Scheme, see :term:`IEEE P1363A <[IEEE P1363A]>`. The
standard operations of GFpEC functions are listed below:


-  Compute a shared secret Z of the private key U and a recipient public
   key W.


-  Derive a shared secret key data K from the shared secret Z.


-  Encrypt or decrypt a message using the cipher agreed upon parties and
   the shared secret key data K.


-  Compute an authentication tag using the agreed authentication scheme
   and the secret key data K.


As an encryption or decryption result, the Elliptic Curve Encryption
Scheme (ECES) returns a buffer with the following components:

* pk containing representation of the sender public key;
*  msg containing the encrypted or decrypted message;
*  tag containing the authentication tag.


The size of msg equals to the size of the plain-text message. To get the
size of pk or tag, call the
:ref:`ippsGFpECESGetBuffersSize_SM2 <gfpecesgetbuffersize_sm2>`
function.


For more information on the SM2 cryptographic algorithm based on
elliptic curves, see :term:`SM2 PKE <[SM2 PKE]>`.

.. toctree::
   :maxdepth: 1


   gfpecesgetsize_sm2
   gfpecesinit_sm2
   gfpecessetkey_sm2
   gfpecesstart_sm2
   gfpecesencrypt_sm2
   gfpecesdecrypt_sm2
   gfpecesfinal_sm2
   gfpecesgetbuffersize_sm2
   gfpecencryptsm2_ext_encmsgsize
   gfpecdecryptsm2_ext_decmsgsize
   gfpecencryptsm2_ext
   gfpecdecryptsm2_ext
   gfpecmessagerepresentationsm2
   gfpecuseridhashsm2
   gfpeckeyexchangesm2_getsize
   gfpeckeyexchangesm2_init
   gfpeckeyexchangesm2_setup
   gfpeckeyexchangesm2_sharedkey
   gfpeckeyexchangesm2_confirm

