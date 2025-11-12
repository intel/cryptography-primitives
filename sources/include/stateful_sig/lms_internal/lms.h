/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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

#ifndef IPPCP_LMS_H_
#define IPPCP_LMS_H_

#include "owndefs.h"
#include "owncp.h"
#include "lmots.h"

/* LMS algorithms params. "Table 2" LMS spec. */
typedef struct {
    Ipp32u m;
    Ipp32u h;
    IppsHashMethod* hash_method;
} cpLMSParams;

/*
 * Non-specified format of LMS private key:
 *  | u32str(type) || u32str(otstype) ||     q    ||   extraBufSize   ||   Secret seed   ||          pI        ||   extra buffer   |
 *  |   4 bytes    ||     4 bytes     ||  4 bytes ||     4 bytes      ||     n bytes     ||  CP_PK_I_BYTESIZE  ||   extraBufSize   |
 */

struct _cpLMSPrivateKeyState {
    Ipp32u _idCtx; // Private key ctx identifier
    IppsLMSAlgo lmsOIDAlgo;
    IppsLMOTSAlgo lmotsOIDAlgo;
    Ipp32u q;
    Ipp32s extraBufSize; // size of memory under pExtraBuf
    Ipp8u* pSecretSeed;
    Ipp8u* pI;
    Ipp8u* pExtraBuf;
};

/*
 * Standard format of LMS public key:
 *  | u32str(type) || u32str(otstype) ||    I     ||   T[1]    |
 *  |    4 bytes   ||     4 bytes     || 16 bytes ||  n bytes  |
*/
struct _cpLMSPublicKeyState {
    Ipp32u _idCtx; // Pub key ctx identifier
    IppsLMSAlgo lmsOIDAlgo;
    IppsLMOTSAlgo lmotsOIDAlgo;
    Ipp8u I[CP_PK_I_BYTESIZE];
    Ipp8u* T1;
};

/*
 * Standard data format for LMS signature
 *  |  4 bytes  ||    ...    ||   4 bytes   ||  n bytes ||  n bytes ||...||  n bytes  |
 *  |     q     || lmots_sig || lms_sigtype ||  path[0] ||  path[1] ||...|| path[h-1] |
 */
struct _cpLMSSignatureState {
    Ipp32u _idCtx; // Signature ctx identifier
    Ipp32u _q;
    _cpLMOTSSignatureState _lmotsSig;
    IppsLMSAlgo _lmsOIDAlgo;
    Ipp8u* _pAuthPath;
    //                  C
    //   Y[0]   ||   Y[1]   ||...||  Y[p-1]
    // path[0] ||  path[1] ||...||  path[h-1]
};

/* Defines to handle contexts IDs */
#define CP_LMS_SET_PRIV_KEY_CTX_ID(ctx) \
    ((ctx)->_idCtx = (Ipp32u)idCtxPrivKeyLMS ^ (Ipp32u)IPP_UINT_PTR(ctx))
#define CP_LMS_SET_PUB_KEY_CTX_ID(ctx) \
    ((ctx)->_idCtx = (Ipp32u)idCtxPubKeyLMS ^ (Ipp32u)IPP_UINT_PTR(ctx))
#define CP_LMS_SET_SIGN_CTX_ID(ctx) \
    ((ctx)->_idCtx = (Ipp32u)idCtxSignLMS ^ (Ipp32u)IPP_UINT_PTR(ctx))
#define CP_LMS_VALID_PRIV_KEY_CTX_ID(ctx) \
    ((((ctx)->_idCtx) ^ (Ipp32u)IPP_UINT_PTR(ctx)) == (Ipp32u)idCtxPrivKeyLMS)
#define CP_LMS_VALID_PUB_KEY_CTX_ID(ctx) \
    ((((ctx)->_idCtx) ^ (Ipp32u)IPP_UINT_PTR(ctx)) == (Ipp32u)idCtxPubKeyLMS)
#define CP_LMS_VALID_SIGN_CTX_ID(ctx) \
    ((((ctx)->_idCtx) ^ (Ipp32u)IPP_UINT_PTR(ctx)) == (Ipp32u)idCtxSignLMS)

/*
 * Set LMS parameters
 *
 * Returns:                Reason:
 *    ippStsBadArgErr         lmsOIDAlgo > Max value for IppsLMSAlgo
 *                            lmsOIDAlgo < Min value for IppsLMSAlgo
 *    ippStsNoErr             no errors
 *
 * Input parameters:
 *    lmsOIDAlgo    id of LMS set of parameters
 *
 * Output parameters:
 *    params    LMS parameters (h, m, hash_method)
 */
IPPCP_INLINE IppStatus setLMSParams(IppsLMSAlgo lmsOIDAlgo, cpLMSParams* params)
{
    /* Set h */
    switch (lmsOIDAlgo % 5) {
    case 0: {
        // LMS_SHA256_M32_H5  and LMS_SHA256_M24_H5
        params->h = 5;
        break;
    }
    case 1: {
        // LMS_SHA256_M32_H10 and LMS_SHA256_M24_H10
        params->h = 10;
        break;
    }
    case 2: {
        // LMS_SHA256_M32_H15 and LMS_SHA256_M24_H15
        params->h = 15;
        break;
    }
    case 3: {
        // LMS_SHA256_M32_H20 and LMS_SHA256_M24_H20
        params->h = 20;
        break;
    }
    case 4: {
        // LMS_SHA256_M32_H25 and LMS_SHA256_M24_H25
        params->h = 25;
        break;
    }
    default:
        return ippStsBadArgErr;
    }

    if (lmsOIDAlgo <= LMS_SHA256_M32_H25) {
        params->m = 32;
    } else {
        params->m = 24;
    }

    params->hash_method = (IppsHashMethod*)ippsHashMethod_SHA256_TT();

    return ippStsNoErr;
}

#define cp_lms_H_tree OWNAPI(cp_lms_H_tree)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_lms_H_tree, (Ipp8u* I,
                                        Ipp32u val1,
                                        Ipp32u val2, const Ipp32s val2Len,
                                        Ipp8u* val3, const Ipp32s val3Len,
                                        Ipp8u* pMsg, const Ipp32s msgLen,
                                        Ipp8u* out,
                                        const IppsHashMethod* hash_method))
/* clang-format on */

#define cp_lms_tree_hash OWNAPI(cp_lms_tree_hash)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_lms_tree_hash, (Ipp8u isKeyGen,
                                           Ipp8u* pSecretSeed,
                                           Ipp8u* pI,
                                           Ipp8u* out,
                                           Ipp32u idx_leaf,
                                           Ipp8u* temp_buf,
                                           Ipp8u* pAuxiliaryMem,
                                           Ipp32s aux_size,
                                           const cpLMSParams* lmsParams,
                                           const cpLMOTSParams* lmotsParams))
/* clang-format on */


#endif /* #ifndef IPPCP_LMS_H_ */
