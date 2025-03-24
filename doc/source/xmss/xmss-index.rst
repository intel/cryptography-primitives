.. _xmss-index:

XMSS
====

Functions such as `XMSS <https://www.rfc-editor.org/info/rfc8391>`__
signature verification and special
functions like getters and setters that are required to call algorithms have been implemented.

Example
-------

.. code:: cpp

    #define IPPCP_PREVIEW_XMSS
    #include "ippcp.h"

    ...

    IppsXMSSAlgo alg_id = IppsXMSSAlgo::XMSS_SHA2_16_256;
    status = ippsXMSSBufferGetSize(&buffSize, sizeof(msg), alg_id);

    status = ippsXMSSPublicKeyStateGetSize(&ippcpPubKeySize, alg_id);

    status = ippsXMSSSignatureStateGetSize(&sigBuffSize, alg_id);

    status = ippsXMSSSetPublicKeyState(alg_id, pRoot, pSeed, pPubKey);

    status = ippsXMSSSetSignatureState(alg_id, idx, r, pOTSSign, pAuthPath, pSignature);

    int is_valid=0;
    status = ippsXMSSVerify(msg, sizeof(msg), pSignature, &is_valid, pPubKey, pScratchBuffer);

    ...

.. toctree::
   :maxdepth: 1

   xmss-verify
   xmss-enum
   xmss-pub-key-get-size
   xmss-sig-get-size
   xmss-buffer-get-size
   xmss-set-pub-key-state
   xmss-set-sig-state
