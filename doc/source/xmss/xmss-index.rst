.. _xmss-index:

XMSS
====

Functions such as `XMSS <https://www.rfc-editor.org/info/rfc8391>`__
key generation, signing, signature verification and special
functions like getters and setters that are required to call algorithms have been implemented.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   XMSS is a stateful algorithm, so users are responsible for storing memory
   for signatures, private keys, and public keys. It is especially important that
   the private key state memory is protected on the user's side.
   See more details in `NIST SP 800-208 <https://csrc.nist.gov/pubs/sp/800/208/final>`__.

Example 1. Key Generation and Signing
-------------------------------------

.. code:: cpp

    #define IPPCP_PREVIEW_XMSS
    #include "ippcp.h"

    ...

    IppsXMSSAlgo alg_id = IppsXMSSAlgo::XMSS_SHA2_16_256;
    status = ippsXMSSKeyGenBufferGetSize(&buffSizeKeyGen, alg_id);
    status = ippsXMSSSignBufferGetSize(&buffSizeSign, sizeof(msg), alg_id);
    status = ippsXMSSVerifyBufferGetSize(&buffSizeVerify, sizeof(msg), alg_id);

    status = ippsXMSSPrivateKeyStateGetSize(&privKeySize, alg_id);
    status = ippsXMSSPublicKeyStateGetSize(&pubKeySize, alg_id);
    status = ippsXMSSSignatureStateGetSize(&signSize, alg_id);

    status = ippsXMSSInitKeyPair(alg_id, pPrvKey, pPubKey);
    status = ippsXMSSInitSignature(alg_id, pSignature);

    status = ippsXMSSKeyGen(pPrvKey, pPubKey, NULL, NULL, pScratchKeyGenBuffer);

    status = ippsXMSSSign(msg, sizeof(msg), pPrvKey, pSignature, pScratchSignBuffer);

    int is_valid=0;
    status = ippsXMSSVerify(msg, sizeof(msg), pSignature, &is_valid, pPubKey, pScratchVerifyBuffer);

    ...

Example 2. Verification
-----------------------

.. code:: cpp

    #define IPPCP_PREVIEW_XMSS
    #include "ippcp.h"

    ...

    IppsXMSSAlgo alg_id = IppsXMSSAlgo::XMSS_SHA2_16_256;
    status = ippsXMSSVerifyBufferGetSize(&buffSize, sizeof(msg), alg_id);

    status = ippsXMSSPublicKeyStateGetSize(&ippcpPubKeySize, alg_id);

    status = ippsXMSSSignatureStateGetSize(&sigBuffSize, alg_id);

    status = ippsXMSSSetPublicKeyState(alg_id, pRoot, pSeed, pPubKey);

    status = ippsXMSSSetSignatureState(alg_id, idx, r, pOTSSign, pAuthPath, pSignature);

    int is_valid=0;
    status = ippsXMSSVerify(msg, sizeof(msg), pSignature, &is_valid, pPubKey, pScratchBuffer);

    ...

.. toctree::
   :maxdepth: 1

   xmss-key-gen
   xmss-sign
   xmss-verify
   xmss-enum
   xmss-key-sig-get-size
   xmss-buffer-get-size
   xmss-set-pub-key-state
   xmss-set-sig-state
   xmss-init-key-state
   xmss-init-sig-state
