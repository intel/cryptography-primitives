.. _functions-for-building-rsa-system:



Functions for Building RSA System
=================================


You can use the primitives to build an RSA cryptographic system with the
supplied randomized seed and stimulus. The function
:ref:`RSA_GenerateKeys <rsa_generatekeys>`
generates key components for the desired RSA cryptographic system.


:ref:`RSA Primitives <rsa-primitives>` and
RSA-based schemes (:ref:`RSA-OAEP Scheme
Functions <rsa-oaep-scheme-functions>` and
:ref:`RSA-SSA Scheme
Functions <rsa-ssa-scheme-functions>`) use
IppsRSAPublicKeyState or IppsRSAPrivateKeyState context, which is
initialized in a call to the :ref:`RSA_InitPublicKey,
RSA_InitPrivateKeyType1, or
RSA_InitPrivateKeyType2 <rsa_initpublickey-privatekeytype1-type2>`
function, as an operational vehicle carrying the RSA public or private
keys.


.. note::


   .. rubric:: Important
      :class: NoteTipHead

   To provide minimum security, the length of the RSA modulus must be
   equal to or greater than 1024 bits.

.. toctree::
   :maxdepth: 1


   rsa_getsizepublickey-rsa_getsizeprivatekeytype1
   rsa_initpublickey-rsa_initprivatekeytype1-rsa
   rsa_setpublickey-rsa-setprivatekeytype1-rsa
   rsa_getpublickey-rsa_getprivatekeytype1-rsa
   rsa_getbuffersizepublickey-rsa
   rsa_mb_getbuffersizepublickey-rsa-mb
   rsa_generatekeys
   rsa_validatekeys