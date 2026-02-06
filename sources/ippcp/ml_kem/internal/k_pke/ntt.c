/*************************************************************************
* Copyright (C) 2025 Intel Corporation
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

#include "owncp.h"
#include "owndefs.h"
#include "stateless_pqc/ml_kem_internal/ml_kem.h"
#include "stateless_pqc/zetas.h"

/*
 * Algorithm 9: NTT(f) - Computes the NTT representation f` of the given polynomial f in R_{q}.
 *
 * Input/Output: f - polynomial Z_{q}^{256}, which is transformed to
 *                   its NTT representation f` in T_{q}.
 */
IPP_OWN_DEFN(void, cp_NTT, (Ipp16sPoly * f))
{
    Ipp16u i = 1;
    for (Ipp16u len = 128; len >= 2; len /= 2) {
        for (Ipp16u start = 0; start < 256; start += 2 * len) {
            Ipp16s zeta = cp_mlkem_zetas_ntt[i];
            i++;
            for (Ipp16u j = start; j < start + len; j++) {
                // delay reduction, as the minimum possible value here will be in the function's range
                Ipp32s t           = (Ipp32s)zeta * f->values[j + len];
                f->values[j + len] = cp_mlkemBarrettReduce(((Ipp32s)f->values[j] - t));
                f->values[j]       = cp_mlkemBarrettReduce(((Ipp32s)f->values[j] + t));
            }
        }
    }
}

/*
 * Algorithm 10: NTT{-1}(f`) - Computes the polynomial f in R_{q} that corresponds to the
 *                             given NTT representation f` in T_{q}.
 *
 * Input/Output: f - polynomial in T_{q}, which is transformed to
 *                   the normal representation Z_{q}^{256}.
 */
IPP_OWN_DEFN(void, cp_inverseNTT, (Ipp16sPoly * f))
{
    Ipp8u i = 127;
    for (Ipp16u len = 2; len <= 128; len *= 2) {
        for (Ipp16u start = 0; start < 256; start += 2 * len) {
            Ipp16s zeta = cp_mlkem_zetas_ntt[i];
            i--;
            for (Ipp16u j = start; j < start + len; j++) {
                Ipp16s t     = f->values[j];
                f->values[j] = cp_mlkemBarrettReduce((Ipp32s)(t + f->values[j + len]));
                // delay reduction, as the minimum possible value here will be in the function's range
                f->values[j + len] = f->values[j + len] - t;
                f->values[j + len] = cp_mlkemBarrettReduce((Ipp32s)zeta * f->values[j + len]);
            }
        }
    }
    for (Ipp16u n = 0; n < 256; n++) {
        f->values[n] = cp_mlkemBarrettReduce((Ipp32s)f->values[n] * 3303);
    }
}

/*
 * Algorithm 12: Computes the product of two degree-one polynomials with respect to
 *               a quadratic modulus.
 *
 * Input:  a0, a1         - coefficients of the first polynomial
 *         b0, b1         - coefficients of the second polynomial
 *         gamma          - zeta^((2*BitReverse_7(i) + 1)) mod q
 * Output: c0_ptr, c1_ptr - pointers to the resulting coefficients
 */
/* clang-format off */
IPPCP_INLINE void cp_baseCaseMultiply(Ipp16s a0, Ipp16s a1,
                                        Ipp16s b0, Ipp16s b1,
                                        Ipp16s gamma,
                                        Ipp16s* c0_ptr, Ipp16s* c1_ptr)
/* clang-format on */
{
    Ipp32s tmpC0 = cp_mlkemBarrettReduce((Ipp32s)a1 * b1);
    tmpC0        = cp_mlkemBarrettReduce((Ipp32s)gamma * tmpC0);
    *c0_ptr      = cp_mlkemBarrettReduce(tmpC0 + (Ipp32s)a0 * b0);

    Ipp32s tmpC1 = cp_mlkemBarrettReduce((Ipp32s)a0 * b1);
    *c1_ptr      = cp_mlkemBarrettReduce((Ipp32s)a1 * b0 + tmpC1);
}

/*
 * Algorithm 11: Computes the product (in the ring T_{q}) of two NTT representations.
 *
 * Input:  f, g - polynomials  Z_{q}^{256} in NTT representation
 * Output: h    - polynomial Z_{q}^{256} in NTT representation
 */
IPP_OWN_DEFN(void, cp_multiplyNTT, (const Ipp16sPoly* f, const Ipp16sPoly* g, Ipp16sPoly* h))
{
    for (Ipp16u i = 0; i < 128; i++) {
        cp_baseCaseMultiply(f->values[2 * i],
                            f->values[2 * i + 1],
                            g->values[2 * i],
                            g->values[2 * i + 1],
                            cp_mlkem_zetas_multiply_ntt[i],
                            &h->values[2 * i],
                            &h->values[2 * i + 1]);
    }
}
