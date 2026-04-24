.. _pkcs-v1.5-signature-scheme-functions:

PKCS V1.5 Signature Scheme Functions
====================================


.. note::


   This algorithm is considered weak due to known attacks on it. The
   functionality remains in the library, but the implementation will no
   longer be optimized and no security patches will be applied. A more
   secure alternative is available: RSA-OAEP. For more information, see
   *PKCS #1 v2.1: RSA Cryptography Standard*
   (https://www.cryptrec.go.jp/en/cryptrec_03_spec_cypherlist_files/PDF/pkcs-1v2-12.pdf).


This subsection describes functions implementing the RSASSA-PKCS1-v1_5
signature scheme with appendix :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`.

.. toctree::
   :maxdepth: 1

   
   rsasign_pkcs1v15
   rsa_mb_sign_pkcs1v15_rmf
   rsaverify_pkcs1v15
   rsa_mb_verify_pkcs1v15_rmf