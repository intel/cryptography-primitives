.. _lms-index:

LMS
===

Functions such as `LMS <https://www.rfc-editor.org/info/rfc8554>`__
signature verification and special
functions like getters and setters that are required to call algorithms have been implemented.

Example
-------

.. code:: cpp

    #define IPPCP_PREVIEW_LMS
    #include "ippcp.h"
    ...

    IppsLMSAlgoType alg_id;
    alg_id.prmLmotsAlg = IppsLMOTSAlgo::LMOTS_SHA256_N32_W8;
    alg_id.prmLmsAlg = IppsLMSAlgo::LMS_SHA256_M24_H10;

    status = ippsLMSVerifyBufferGetSize(&buffSize, sizeof(msg), alg_id);

    status = ippsLMSPublicKeyStateGetSize(&ippcpPubKeySize, alg_id);

    status = ippsLMSSignatureStateGetSize(&sigBuffSize, alg_id);

    status = ippsLMSSetPublicKeyState(alg_id, pI, pK, pPubKey);

    status = ippsLMSSetSignatureState(alg_id, q, pC, pY, pAuthPath, pSignature);

    int is_valid=0;
    status = ippsLMSVerify(msg, sizeof(msg), pSignature, &is_valid, pPubKey, pScratchBuffer);

    ...

.. toctree::
   :maxdepth: 1

   verify
   enum
   pub-key-get-size
   sig-get-size
   buffer-get-size
   set-pub-key-state
   set-sig-state
