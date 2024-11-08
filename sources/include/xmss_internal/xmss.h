/*************************************************************************
* Copyright (C) 2023 Intel Corporation
*
* Licensed under the Apache License,  Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* 	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law  or agreed  to  in  writing,  software
* distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the  specific  language  governing  permissions  and
* limitations under the License.
*************************************************************************/

#ifndef IPPCP_XMSS_H_
#define IPPCP_XMSS_H_

#include "owndefs.h"
#include "owncp.h"
#include "wots.h"

// The format of an XMSS public key
// +---------------------------------+
// | algorithm OID                   |
// +---------------------------------+
// |                                 |
// | root node                       | n bytes
// |                                 |
// +---------------------------------+
// |                                 |
// | SEED                            | n bytes
// |                                 |
// +---------------------------------+

struct _cpXMSSPublicKeyState {
    IppsXMSSAlgo OIDAlgo;
    Ipp8u* pRoot;
    Ipp8u* pSeed;
};

// The data format for a signature
// +---------------------------------+
// |                                 |
// | index idx_sig                   | 4 bytes
// |                                 |
// +---------------------------------+
// |                                 |
// | randomness r                    | n bytes
// |                                 |
// +---------------------------------+
// |                                 |
// | WOTS+ signature sig_ots         | len * n bytes
// |                                 |
// +---------------------------------+
// |                                 |
// | auth[0]                         | n bytes
// |                                 |
// +---------------------------------+
// |                                 |
// ˜                 ....            ˜
// |                                 |
// +---------------------------------+
// |                                 |
// | auth[h - 1]                     | n bytes
// |                                 |
// +---------------------------------+

struct _cpXMSSSignatureState {
    Ipp32u idx;
    Ipp8u* r;
    Ipp8u* pOTSSign;
    Ipp8u* pAuthPath;
};

// declarations
#define ltree OWNAPI(ltree)
IPP_OWN_DECL(IppStatus, ltree, (Ipp8u* pk, Ipp8u* seed, Ipp8u* adrs, Ipp8u* temp_buf, cpWOTSParams* params))

#define rand_hash OWNAPI(rand_hash)
IPP_OWN_DECL(IppStatus, rand_hash, (Ipp8u* left, Ipp8u* right, Ipp8u* seed,
            Ipp8u* adrs, Ipp8u* out, Ipp8u* temp_buf, cpWOTSParams* params))

/*
 * Set XMSS algorithms parameters
 *
 * Returns:                Reason:
 *    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
 *                            OIDAlgo <= 0
 *    ippStsNoErr             no errors
 *
 * Input parameters:
 *    OIDAlgo   id of XMSS set of parameters (algorithm)
 *    h         height of the XMSS tree
 *
 * Output parameters:
 *    params    WOTS parameters (w, log2_w, n, len, len_1, hash_method)
 */

__IPPCP_INLINE IppStatus setXMSSParams(IppsXMSSAlgo OIDAlgo, Ipp32s* h, cpWOTSParams* params) {

    // Digits below are from the XMSS algo spec
    // don't depend on the algo
    params->w = 16;
    params->log2_w = 4;

    // 256-bit or 512-bit
    if(OIDAlgo > 0 && OIDAlgo < 4) {
        params->n = 32;
        params->len = 67;
        params->len_1 = 64;
        params->hash_method = (IppsHashMethod*) ippsHashMethod_SHA256_TT();
    }
    else if(OIDAlgo > 3 && OIDAlgo < 7) {
        params->n = 64;
        params->len = 131;
        params->len_1 = 128;
        params->hash_method = (IppsHashMethod*) ippsHashMethod_SHA512_TT();
    }
    else {
        return ippStsBadArgErr;
    }

    // tree height
    if(OIDAlgo % 3 == 1) {
        *h = 10;
    }
    else if(OIDAlgo % 3 == 2) {
        *h = 16;
    }
    else if(OIDAlgo % 3 == 0) {
        *h = 20;
    }

    return ippStsNoErr;
}

#endif /* #ifndef IPPCP_XMSS_H_ */

