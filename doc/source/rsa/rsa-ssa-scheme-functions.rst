.. _rsa-ssa-scheme-functions:




RSA-SSA Scheme Functions
========================


This subsection describes functions implementing RSASSA-PSS_5 signature
scheme with appendix :term:`PKCS 1.2.1 <[PKCS 1.2.1]>`.


To invoke
:ref:`RSASign_PSS <rsasign_pss>` or
:ref:`RSAVerify_PSS <rsaverify_pss>`
primitive, supply the IppsRSAPrivateKeyState and/or
IppsRSAPublicKeyState context initialized by a suitable function (see
:ref:`RSA_InitPublicKey, RSA_InitPrivateKeyType1, or
RSA_InitPrivateKeyType2 <rsa_initpublickey-privatekeytype1-type2>` for details).

.. toctree::
   :maxdepth: 1


   rsasign_pss
   rsa_mb_sign_pss_rmf
   rsaverify_pss
   rsa_mb_verify_pss_rmf