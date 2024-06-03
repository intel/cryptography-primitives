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
#include "lms_internal/lmots.h"

#define CP_CKSM_BYTESIZE         (2)
#define CP_PK_I_BYTESIZE         (16)
#define CP_LMS_MAX_HASH_BYTESIZE (32)
#define CP_SIG_MAX_Y_WORDSIZE    (265)

/* Constants used to distinguish hashes in the system */
#define D_PBLC (0x8080)
#define D_MESG (0x8181)
#define D_LEAF (0x8282)
#define D_INTR (0x8383)

/* LMS algorithms params. "Table 2" LMS spec. */
typedef struct {
    Ipp32u m;
    Ipp32u h;
    IppsHashMethod* hash_method;
} cpLMSParams;

/*
 * Standard format of LMS public key:
 *  | u32str(type) || u32str(otstype) ||    I     ||   T[1]    |
 *  |    4 bytes   ||     4 bytes     || 16 bytes ||  n bytes  |
*/
struct _cpLMSPublicKeyState {
    Ipp32u _idCtx;           // Pub key ctx identifier
    IppsLMSAlgo   lmsOIDAlgo;
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
    Ipp32u _idCtx;  // Signature ctx identifier
    Ipp32u _q;
    _cpLMOTSSignatureState _lmotsSig;
    IppsLMSAlgo _lmsOIDAlgo;
    Ipp8u* _pAuthPath;
    // path[0] ||  path[1] ||...||  path[h-1]
    //                  C
    //   Y[0]   ||   Y[1]   ||...||  Y[p-1]
};

/* Defines to handle contexts IDs */
#define CP_LMS_SET_CTX_ID(ctx)    ((ctx)->_idCtx = (Ipp32u)idCtxLMS ^ (Ipp32u)IPP_UINT_PTR(ctx))
#define CP_LMS_VALID_CTX_ID(ctx)  ((((ctx)->_idCtx) ^ (Ipp32u)IPP_UINT_PTR(ctx)) == (Ipp32u)idCtxLMS)

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
__IPPCP_INLINE IppStatus setLMSParams(IppsLMSAlgo lmsOIDAlgo, cpLMSParams* params) {
    /* Set h */
    switch (lmsOIDAlgo % 5) {
        case 0: { params->h = 5;  break; } // LMS_SHA256_M32_H5  and LMS_SHA256_M24_H5
        case 1: { params->h = 10; break; } // LMS_SHA256_M32_H10 and LMS_SHA256_M24_H10
        case 2: { params->h = 15; break; } // LMS_SHA256_M32_H15 and LMS_SHA256_M24_H15
        case 3: { params->h = 20; break; } // LMS_SHA256_M32_H20 and LMS_SHA256_M24_H20
        case 4: { params->h = 25; break; } // LMS_SHA256_M32_H25 and LMS_SHA256_M24_H25
        default: return ippStsBadArgErr;
    }

    if(lmsOIDAlgo <= LMS_SHA256_M32_H25) {
        params->m = 32;
    }
    else {
        params->m = 24;
    }

    params->hash_method = (IppsHashMethod*) ippsHashMethod_SHA256_TT();

    return ippStsNoErr;
}

#endif /* #ifndef IPPCP_LMS_H_ */
