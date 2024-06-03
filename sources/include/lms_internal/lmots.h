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

#ifndef IPPCP_LMOTS_H_
#define IPPCP_LMOTS_H_

#include "owndefs.h"
#include "pcptool.h"

#include "stateful_sig_common/common.h"

/*
 * LMOTS algorithms params. "Table 1" LMS spec.
 */
typedef struct {
    Ipp32u n;
    Ipp32u w;
    Ipp32u p;
    Ipp32u ls;
    IppsHashMethod* hash_method;
} cpLMOTSParams;

/*
 * Standard data format for LMOTS signature
 *  |  4 bytes   || n bytes || n bytes || n bytes ||...|| n bytes |
 *  | otssigtype ||    C    ||   Y[0]  ||   Y[1]  ||...||  Y[p-1] |
 */
typedef struct {
    IppsLMOTSAlgo _lmotsOIDAlgo;
    Ipp8u* pC;
    Ipp8u* pY;
} _cpLMOTSSignatureState;

/*
 * Set LMOTS parameters
 *
 * Returns:                Reason:
 *    ippStsBadArgErr         lmotsOIDAlgo > Max value for IppsLMOTSAlgo
 *                            lmotsOIDAlgo <= 0
 *    ippStsNoErr             no errors
 *
 * Input parameters:
 *    lmotsOIDAlgo   id of LMOTS set of parameters
 *
 * Output parameters:
 *    params         LMOTS parameters (w, p, ls, n, hash_method)
 */
__IPPCP_INLINE IppStatus setLMOTSParams(IppsLMOTSAlgo lmotsOIDAlgo, cpLMOTSParams* params) {
    switch (lmotsOIDAlgo) {
        case LMOTS_SHA256_N32_W1: {
            params->w = 1;
            params->p = 265;
            params->ls = 7;
            break;
        }
        case LMOTS_SHA256_N32_W2: {
            params->w = 2;
            params->p = 133;
            params->ls = 6;
            break;
        }
        case LMOTS_SHA256_N32_W4: {
            params->w = 4;
            params->p = 67;
            params->ls = 4;
            break;
        }
        case LMOTS_SHA256_N32_W8: {
            params->w = 8;
            params->p = 34;
            params->ls = 0;
            break;
        }
        case LMOTS_SHA256_N24_W1: {
            params->w = 1;
            params->p = 200;
            params->ls = 8;
            break;
        }
        case LMOTS_SHA256_N24_W2: {
            params->w = 2;
            params->p = 101;
            params->ls = 6;
            break;
        }
        case LMOTS_SHA256_N24_W4 : {
            params->w = 4;
            params->p = 51;
            params->ls = 4;
            break;
        }
        case LMOTS_SHA256_N24_W8 : {
            params->w = 8;
            params->p = 26;
            params->ls = 0;
            break;
        }
        default: return ippStsBadArgErr;
    }
    params->hash_method = (IppsHashMethod*) ippsHashMethod_SHA256_TT();

    if(lmotsOIDAlgo <= LMOTS_SHA256_N32_W8) {
        params->n = 32;
    }
    else {
        params->n = 24;
    }
    return ippStsNoErr;
}

/*
 * f(S, i, w) is the i-th, w-bit value, if S
 * is interpreted as a sequence of w-bit values
 *
 * Input parameters:
 *    S    a string to calculate coef
 *    i    output element position
 *    w    the length of the output element
 *
 * Output parameters:
 *    Target element of a specified length
 *
 */
__IPPCP_INLINE Ipp32u cpCoef(Ipp8u* S, Ipp32u i, Ipp32u w) {
    return ((1 << w) - 1) & ( S[(i * w) / 8] >> (8 - (w * (i % (8 / w)) + w)));
}

__IPPCP_INLINE Ipp32u cpCksm(Ipp8u* S, cpLMOTSParams lmotsParams) {
    Ipp32u w = lmotsParams.w;
    Ipp32u n = lmotsParams.n;
    Ipp32u ls = lmotsParams.ls;

    Ipp32u cksmQ = 0; //sum is a 16-bit unsigned integer
    Ipp32u cksmItrLimit = (8 * n) / w;
    for (Ipp32u i = 0; i < cksmItrLimit; i++) {
        cksmQ = cksmQ + ((1 << w) - 1) - cpCoef(S, i, w);
    }
    cksmQ = cksmQ << ls;

    return cksmQ;
}

#endif /* #ifndef IPPCP_LMOTS_H_ */
