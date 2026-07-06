.. _lms-index:

LMS
===

Functions such as `LMS <https://www.rfc-editor.org/info/rfc8554>`__
key generation, signing, signature verification and special
functions like getters and setters that are required to call algorithms have been implemented.

.. note::

   .. rubric:: Important
      :class: NoteTipHead

   LMS is a stateful algorithm, so users are responsible for storing memory
   for signatures, private keys, and public keys. It is especially important that
   the private key state memory is protected on the user's side.
   See more details in `RFC 8554 <https://datatracker.ietf.org/doc/rfc8554>`__.

Example 1. Key Generation and Signing
-------------------------------------

.. code:: cpp

    #define IPPCP_PREVIEW_LMS
    #include "ippcp.h"

    ...

    IppsLMSAlgoType alg_id;
    alg_id.prmLmotsAlg = IppsLMOTSAlgo::LMOTS_SHA256_N32_W8;
    alg_id.prmLmsAlg = IppsLMSAlgo::LMS_SHA256_M24_H10;
    int extra_buf_size = 320;

    status = ippsLMSKeyGenBufferGetSize(&buffSizeKeyGen, alg_id);
    status = ippsLMSSignBufferGetSize(&buffSizeSign, sizeof(msg), alg_id);
    status = ippsLMSVerifyBufferGetSize(&buffSizeVerify, sizeof(msg), alg_id);

    status = ippsLMSPrivateKeyStateGetSize(&privKeySize, alg_id, extra_buf_size);
    status = ippsLMSPublicKeyStateGetSize(&pubKeySize, alg_id);
    status = ippsLMSSignatureStateGetSize(&signSize, alg_id);

    status = ippsLMSInitKeyPair(alg_id, extra_buf_size, pPrvKey, pPubKey);
    status = ippsLMSInitSignature(alg_id, pSignature);

    status = ippsLMSKeyGen(pPrvKey, pPubKey, NULL, NULL, pScratchKeyGenBuffer);

    status = ippsLMSSign(msg, sizeof(msg), pPrvKey, pSignature, NULL, NULL, pScratchSignBuffer);

    int is_valid=0;
    status = ippsLMSVerify(msg, sizeof(msg), pSignature, &is_valid, pPubKey, pScratchVerifyBuffer);

    ...

Example 2. Verification
-----------------------

.. code:: cpp

    #define IPPCP_PREVIEW_LMS
    #include "ippcp.h"
    ...

    IppsLMSAlgoType alg_id;
    alg_id.prmLmotsAlg = IppsLMOTSAlgo::LMOTS_SHA256_N32_W8;
    alg_id.prmLmsAlg = IppsLMSAlgo::LMS_SHA256_M24_H10;

    status = ippsLMSVerifyBufferGetSize(&buffSize, sizeof(msg), alg_id);

    status = ippsLMSPublicKeyStateGetSize(&pubKeySize, alg_id);

    status = ippsLMSSignatureStateGetSize(&sigBuffSize, alg_id);

    status = ippsLMSSetPublicKeyState(alg_id, pI, pK, pPubKey);

    status = ippsLMSSetSignatureState(alg_id, q, pC, pY, pAuthPath, pSignature);

    int is_valid=0;
    status = ippsLMSVerify(msg, sizeof(msg), pSignature, &is_valid, pPubKey, pScratchBuffer);

    ...

.. toctree::
   :maxdepth: 1

   key-gen
   sign
   verify
   enum
   key-sig-get-size
   buffer-get-size
   set-pub-key-state
   set-priv-key-state
   set-sig-state
   init-key-state
   init-sig-state
