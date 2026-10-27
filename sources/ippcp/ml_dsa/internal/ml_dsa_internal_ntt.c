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

// Forward NTT (Cooley-Tukey) for CPUs below l9; l9 and above use ml_dsa_internal_ntt_avx2.c.
// The loops are arranged so the compiler can vectorize them. Wide layers (len >= 8) keep the
// natural j-inner loop; narrow layers (len 4, 2, 1) swap the loops, see below. Butterflies
// within a layer are independent, so the order does not change the result.
//
// Lazy reduction: the per-layer conditional subtract of Q is dropped. Output stays congruent
// mod Q but non-canonical. Worst case: cp_ml_montgomeryReduce gives |t| < Q, and each layer
// only adds t to the running value, so the bound grows additively to Q + 8Q = 9Q (75423753),
// far inside int32. Every consumer reduces (montgomery / Barrett).
//
// Boundary between the two loop nests. Must be a power of two in [2, CP_ML_N / 2]: the loops
// step by >>= 1 / <<= 1 so the wide and narrow ranges partition the 8 layers exactly, and the
// narrow nest seeds at CP_ML_NTT_VEC_LEN / 2.
#define CP_ML_NTT_VEC_LEN 8

// Algorithm 41 NTT(w)
IPP_OWN_DEFN(void, cp_ml_NTT, (IppPoly * f))
{
    Ipp32u zetaIdx = 1;
    for (Ipp32u len = CP_ML_N / 2; len >= CP_ML_NTT_VEC_LEN; len >>= 1) {
        for (Ipp32u start = 0; start < CP_ML_N; start += 2 * len) {
            Ipp64s zeta = cp_mldsa_montgomery_zetas_ntt[zetaIdx++];
            for (Ipp32u j = start; j < start + len; j++) {
                Ipp32s t           = cp_ml_montgomeryReduce(zeta * (Ipp64s)f->values[j + len]);
                f->values[j + len] = (f->values[j] - t);
                f->values[j]       = (f->values[j] + t);
            }
        }
    }
    // Narrow layers (len = 4, 2, 1). Here the natural inner loop spans only len elements, too
    // few to fill a vector, so the nest is swapped: the inner loop walks the numBlocks
    // independent butterflies (32, 64, 128 of them) that sit at a fixed offset inside their
    // block, and the outer loop steps that offset across the block. Same butterflies as the
    // j-inner form, visited in a different order, so the result is bit-identical. Each block
    // uses its own zeta, hence zetaBase + block.
    for (Ipp32u len = CP_ML_NTT_VEC_LEN / 2; len >= 1; len >>= 1) {
        Ipp32u numBlocks = CP_ML_N / (2 * len);
        Ipp32u zetaBase  = zetaIdx;
        for (Ipp32u offset = 0; offset < len; offset++) {
            for (Ipp32u block = 0; block < numBlocks; block++) {
                Ipp32u j           = block * 2 * len + offset;
                Ipp64s zeta        = cp_mldsa_montgomery_zetas_ntt[zetaBase + block];
                Ipp32s t           = cp_ml_montgomeryReduce(zeta * (Ipp64s)f->values[j + len]);
                f->values[j + len] = (f->values[j] - t);
                f->values[j]       = (f->values[j] + t);
            }
        }
        zetaIdx += numBlocks;
    }
    return;
}

// Algorithm 42 NTT^−1(w). Same loop layout as cp_ml_NTT, in reverse order: narrow layers first
// with swapped loops, then wide layers.
IPP_OWN_DEFN(void, cp_ml_inverseNTT, (IppPoly * w, int addq))
{
    // Precondition: |w[i]| < Q on entry. All producers meet it (cp_ml_multiplyNTT ends in
    // cp_ml_montgomeryReduce; cp_ml_addNTT / cp_ml_subNTT in cp_ml_simplifiedBarrettReduce).
    //
    // Lazy reduction: per-layer conditional subtract dropped (see cp_ml_NTT). Congruence is
    // unaffected; the bound is what needs care. The sum side pairs two values per layer, so
    // B_0 = Q and B_{k+1} = 2 B_k, giving B_8 = 2^8 Q. The difference side stays under Q
    // because cp_ml_montgomeryReduce needs |a| < 2^31 Q and gets at most Q * 2 B_7. Both
    // facts reduce to 2^8 Q = 2145386752 <= 2^31, a 0.098% margin, and it is tight: index 0
    // sums all 256 inputs, sup 256 (Q-1) = 2145386496. An input at 2Q would need 2^9 Q and
    // overflow (UB). The n^-1 sweep and optional addq pass normalize the output.
    Ipp32u zetaIdx = CP_ML_N;
    for (Ipp32u len = 1; len < CP_ML_NTT_VEC_LEN; len <<= 1) {
        Ipp32u numBlocks = CP_ML_N / (2 * len);
        Ipp32u zetaBase  = zetaIdx;
        for (Ipp32u offset = 0; offset < len; offset++) {
            for (Ipp32u block = 0; block < numBlocks; block++) {
                Ipp32u j           = block * 2 * len + offset;
                Ipp32s z           = -cp_mldsa_montgomery_zetas_ntt[zetaBase - 1 - block];
                Ipp32s t           = w->values[j];
                w->values[j]       = (t + w->values[j + len]);
                w->values[j + len] = (t - w->values[j + len]);
                w->values[j + len] = cp_ml_montgomeryReduce((Ipp64s)z * w->values[j + len]);
            }
        }
        zetaIdx -= numBlocks;
    }
    for (Ipp32u len = CP_ML_NTT_VEC_LEN; len < CP_ML_N; len <<= 1) {
        for (Ipp32u start = 0; start < CP_ML_N; start += 2 * len) {
            Ipp32s z = -cp_mldsa_montgomery_zetas_ntt[--zetaIdx];
            for (Ipp32u j = start; j < start + len; ++j) {
                Ipp32s t           = w->values[j];
                w->values[j]       = (t + w->values[j + len]);
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
