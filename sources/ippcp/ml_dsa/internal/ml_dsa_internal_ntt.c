/*************************************************************************
* Copyright (C) 2026 Intel Corporation
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

#include "owndefs.h"
#include "ippcpdefs.h"
#include "stateless_pqc/ml_dsa/ml_dsa.h"
#include "stateless_pqc/common.h"
#include "stateless_pqc/zetas.h"

#if !(_IPP32E >= _IPP32E_L9)

// Algorithm 45 MultiplyNTT(𝑎,̂𝑏)
IPP_OWN_DEFN(void, cp_ml_multiplyNTT, (const IppPoly* a, const IppPoly* b, IppPoly* c))
{
    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        c->values[i] = cp_ml_montgomeryReduce((Ipp64s)(a->values[i]) * (b->values[i]));
    }
    return;
}

// Algorithm 41 NTT(w)
IPP_OWN_DEFN(void, cp_ml_NTT, (IppPoly * f))
{
    Ipp32u i = 1;
    for (Ipp8u len = CP_ML_N / 2; len >= 1; len >>= 1) {
        for (Ipp32u start = 0; start < CP_ML_N; start += 2u * len) {
            Ipp64s zeta = cp_mldsa_montgomery_zetas_ntt[i];
            i++;
            for (Ipp32u j = start; j < start + len; j++) {
                Ipp32s t           = cp_ml_montgomeryReduce(zeta * (Ipp64s)f->values[j + len]);
                f->values[j + len] = (f->values[j] - t);
                f->values[j]       = (f->values[j] + t);
                f->values[j] -= (-(f->values[j] >= CP_ML_DSA_Q)) & CP_ML_DSA_Q;
            }
        }
    }
    return;
}

// Algorithm 42 NTT^−1(w)
IPP_OWN_DEFN(void, cp_ml_inverseNTT, (IppPoly * w, int addq))
{
    Ipp32u m = CP_ML_N;
    for (Ipp32u len = 1; len < CP_ML_N; len <<= 1) {
        for (Ipp32u start = 0; start < CP_ML_N; start += 2 * len) {
            m--;
            Ipp32s z = -cp_mldsa_montgomery_zetas_ntt[m];
            for (Ipp32u j = start; j < start + len; ++j) {
                Ipp32s t     = w->values[j];
                w->values[j] = (t + w->values[j + len]);
                w->values[j] -= (-(w->values[j] >= CP_ML_DSA_Q)) & CP_ML_DSA_Q;
                w->values[j + len] = (t - w->values[j + len]);
                w->values[j + len] = cp_ml_montgomeryReduce((Ipp64s)z * w->values[j + len]);
            }
        }
    }

    Ipp64s f = 41978; // (((2 ^ 32) ^ 2) / N) % Q
    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        w->values[i] = cp_ml_montgomeryReduce((Ipp64s)f * w->values[i]);
    }

    // extra reduce step for montgomery to add q (comparison mask, see cp_ml_barrettReduce)
    if (addq == 1) {
        for (Ipp32u j = 0; j < CP_ML_N; ++j) {
            w->values[j] = cp_ml_simplifiedBarrettReduce(
                w->values[j] + ((-(Ipp32s)(w->values[j] < 0)) & CP_ML_DSA_Q));
        }
    }
    return;
}

#endif // #if !(_IPP32E >= _IPP32E_L9)
