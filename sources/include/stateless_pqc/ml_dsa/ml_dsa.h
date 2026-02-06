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

#ifndef _IPPCP_ML_DSA_H_
#define _IPPCP_ML_DSA_H_

#include "owndefs.h"
#include "pcptool.h"
#include "stateless_pqc/zetas.h"

typedef struct {
    Ipp8u* pStorageData;   // pointer to the actual memory (placed in the working buffers)
    Ipp32s bytesCapacity;  // bytesize of the storage for current operation
    Ipp32s bytesUsed;      // number of used bytes in the storage for current operation
    Ipp32s keyGenCapacity; // total bytesize of the storage for keyGen operation
    Ipp32s signCapacity;   // total bytesize of the storage for sign operation
    Ipp32s verifyCapacity; // total bytesize of the storage for verify operation
} _cpMLDSAStorage;

#define POLY_VALUE_T Ipp32s
#define STORAGE_T    _cpMLDSAStorage

#include "stateless_pqc/common.h"

typedef struct {
    Ipp32s gamma_1;
    Ipp32s gamma_2;
    Ipp8u tau;
    Ipp8u lambda_div_4;
    Ipp8u k;
    Ipp8u l;
    Ipp8u eta;
    Ipp8u beta;
    Ipp8u omega;
} _cpMLDSAParams;

struct _cpMLDSAState {
    _cpMLDSAParams params;   // ML DSA parameters
    Ipp32u idCtx;            // state's Id
    _cpMLDSAStorage storage; // management of the temporary data storage(variables, hash states)
};

/* State ID set\check helpers */
#define CP_ML_DSA_SET_ID(pCtx)   ((pCtx)->idCtx = (Ipp32u)idCtxMLDSA ^ (Ipp32u)IPP_UINT_PTR(pCtx))
#define CP_ML_DSA_VALID_ID(pCtx) ((((pCtx)->idCtx) ^ (Ipp32u)IPP_UINT_PTR(pCtx)) == idCtxMLDSA)

/* ML-DSA constants */
#define CP_ML_DSA_Q          (8380417)
#define CP_ML_DSA_D          (13)
#define CP_ML_DSA_N_BLOCKS   (32)
#define CP_ML_DSA_BITLEN_Q_D (10) // cp_ml_bitlen(CP_ML_DSA_Q - 1) - CP_ML_DSA_D

#define CP_ML_DSA_MAX_SIGN_ITERATIONS             (815)
#define CP_ML_DSA_MAX_REJ_BOUNDED_POLY_ITERATIONS (482)
#define CP_ML_DSA_MAX_REJ_NTT_POLY_ITERATIONS     (299)
#define CP_ML_DSA_MAX_SAMPLE_IN_BALL_ITERATIONS   (122)

//-------------------------------//
// Kernel functions declaration
//-------------------------------//

// The bit length of b is the number of digits that would appear in a base-2 representation of b,
// where the most significant digit in the representation is assumed to be a 1 (e.g., bitlen 32 = 6 and bitlen 31 = 5).
IPPCP_INLINE Ipp8u cp_ml_bitlen(Ipp32u b)
{
    Ipp8u len = 0;
    while (b > 0) {
        len++;
        b >>= 1;
    }
    return len;
}

// =============================================
// 7.1 Conversion Between Data Types
// =============================================

// Algorithm 14 CoeffFromThreeBytes(𝑏0, 𝑏1, 𝑏2)
IPPCP_INLINE Ipp32s cp_ml_coeffFromThreeBytes(Ipp8u b0, Ipp8u b1, Ipp8u b2)
{
    if (b2 > 127) {
        b2 -= 128;
    }
    Ipp32s z = ((Ipp32s)(b0)) + (((Ipp32s)(b1)) << 8) + (((Ipp32s)(b2)) << 16);
    return (z < CP_ML_DSA_Q) ? z : -1;
}

// Algorithm 15 CoeffFromHalfByte(𝑏)
IPPCP_INLINE Ipp8s cp_ml_coeffFromHalfByte(Ipp8u b, Ipp8u eta)
{
    Ipp8s b_s = (Ipp8s)b;
    if (eta == 2 && b < 15) {
        // 2 - (b % 5);
        return 2 - (b_s - (b_s / 5) * 5);
    } else if (eta == 4 && b < 9) {
        return 4 - b_s;
    }
    return -100;
}

// Algorithm 16 SimpleBitPack(𝑤, 𝑏)
IPPCP_INLINE void cp_ml_simpleBitPack(const IppPoly* w, const Ipp32u bitlen_b, Ipp8u* out)
{
    for (Ipp32u i = 0; i < 32 * bitlen_b; i++) {
        out[i] = 0;
    }

    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        Ipp32s temp = w->values[i];
        for (Ipp32u ii = 0; ii < bitlen_b; ii++) {
            Ipp32u idx = i * bitlen_b + ii;
            out[idx >> 3] |= (Ipp8u)((temp & 1) << (idx & 7));
            temp >>= 1;
        }
    }
}

// Algorithm 17 BitPack(𝑤, 𝑎, 𝑏)
IPPCP_INLINE void cp_ml_bitPack(const IppPoly* w, Ipp32s b, Ipp32u bitlen_ab, Ipp8u* out)
{
    for (Ipp32u i = 0; i < 32 * bitlen_ab; i++) {
        out[i] = 0;
    }

    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        Ipp32s temp = b - w->values[i];
        for (Ipp32u ii = 0; ii < bitlen_ab; ii++) {
            Ipp32u idx = i * bitlen_ab + ii;
            out[idx >> 3] |= (Ipp8u)((temp & 1) << (idx & 7));
            temp >>= 1;
        }
    }
}

// Algorithm 18 SimpleBitUnpack(v, b)
// length of v = 32 * bitlen b
IPPCP_INLINE void cp_ml_simpleBitUnpack(const Ipp8u* v, Ipp32u bitlen_b, IppPoly* out)
{
    for (int i = 0; i < CP_ML_N; i++) {
        out->values[i] = 0;
    }

    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        Ipp32s temp = 0;

        // Extract c bits for this coefficient, processing from MSB to LSB
        for (Ipp32u j = 0; j < bitlen_b; j++) {
            Ipp32u bitPosition = i * bitlen_b + (bitlen_b - 1 - j); // Reverse bit order

            Ipp8u bitValue = (v[bitPosition >> 3] >> (bitPosition & 7)) & 1;
            temp           = (temp << 1) | bitValue;
        }

        out->values[i] = temp;
    }
}

// Algorithm 19 BitUnpack(𝑣, 𝑎, 𝑏)
IPPCP_INLINE void cp_ml_bitUnpack(const Ipp8u* v, Ipp32s b, Ipp32u bitlen_ab, IppPoly* out)
{
    for (int i = 0; i < CP_ML_N; i++) {
        out->values[i] = 0;
    }

    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        Ipp32s temp = 0;

        // Extract c bits for this coefficient, processing from MSB to LSB
        for (Ipp32u j = 0; j < bitlen_ab; j++) {
            Ipp32u bitPosition = i * bitlen_ab + (bitlen_ab - 1 - j); // Reverse bit order

            Ipp8u bitValue = (v[bitPosition >> 3] >> (bitPosition & 7)) & 1;
            temp           = (temp << 1) | bitValue;
        }

        out->values[i] = b - temp;
    }
}

// Algorithm 20 HintBitPack(𝐡)
IPPCP_INLINE void cp_ml_hintBitPack(const IppPoly* h, Ipp8u omega, Ipp8u k, Ipp8u* out)
{
    for (Ipp32u i = 0; i < (Ipp32u)omega + k; i++) {
        out[i] = 0;
    }
    Ipp8u index = 0;
    for (Ipp8u i = 0; i < k; ++i) {
        for (Ipp32u j = 0; j < CP_ML_N; ++j) {
            if (h[i].values[j] != 0) {
                out[index] = (Ipp8u)j;
                index++;
            }
        }
        out[omega + i] = index;
    }
}

// Algorithm 21 HintBitUnpack(𝑦)
IPPCP_INLINE IppStatus cp_ml_hintBitUnpack(const Ipp8u* y, Ipp8u omega, Ipp8u k, IppPoly* h)
{
    Ipp8u index = 0;
    for (Ipp8u i = 0; i < k; ++i) {
        for (Ipp32u j = 0; j < CP_ML_N; ++j) {
            h[i].values[j] = 0;
        }
        if (y[omega + i] < index || y[omega + i] > omega) {
            return ippStsOutOfRangeErr;
        }
        Ipp8u first = index;
        while (index < y[omega + i]) {
            if (index > first) {
                if (y[index - 1] >= y[index]) {
                    return ippStsOutOfRangeErr;
                }
            }
            h[i].values[y[index]] = 1;
            index++;
        }
    }
    for (Ipp8u i = index; i < omega; ++i) {
        if (y[i] != 0) {
            return ippStsOutOfRangeErr;
        }
    }
    return ippStsNoErr;
}

// =============================================
// 7.2 Encodings of ML-DSA Keys and Signatures
// =============================================

// Algorithm 22 pkEncode(rho, t1)
IPPCP_INLINE void cp_ml_pkEncode(const Ipp8u* rho,
                                 const IppPoly* t1,
                                 Ipp8u* pk,
                                 IppsMLDSAState* mldsaCtx)
{
    // Copy rho
    CopyBlock(rho, pk, 32);

    // Encode t1
    Ipp8u* pEncodedT1 = pk + 32;

    for (Ipp8u i = 0; i < mldsaCtx->params.k; i++) {
        cp_ml_simpleBitPack(t1 + i,
                            CP_ML_DSA_BITLEN_Q_D,
                            pEncodedT1 + i * 32 * CP_ML_DSA_BITLEN_Q_D);
    }
}

// Algorithm 23 pkDecode(𝑝𝑘)
IPPCP_INLINE void cp_ml_pkDecode(const Ipp8u* pk, IppPoly* t1, IppsMLDSAState* mldsaCtx)
{
    // Decode t1
    const Ipp8u* pEncodedT1 = pk + 32;
    for (Ipp8u i = 0; i < mldsaCtx->params.k; i++) {
        cp_ml_simpleBitUnpack(pEncodedT1 + i * 32 * CP_ML_DSA_BITLEN_Q_D,
                              CP_ML_DSA_BITLEN_Q_D,
                              t1 + i);
    }
}

// Algorithm 24 skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
IPPCP_INLINE void cp_ml_skEncode(const Ipp8u* rho,
                                 const Ipp8u* K,
                                 const Ipp8u* tr,
                                 const IppPoly* s1,
                                 const IppPoly* s2,
                                 const IppPoly* t0,
                                 Ipp8u* sk,
                                 IppsMLDSAState* mldsaCtx)
{
    Ipp16u sk_position = 0;

    CopyBlock(rho, sk, 32);
    sk_position += 32;

    CopyBlock(K, sk + sk_position, 32);
    sk_position += 32;

    CopyBlock(tr, sk + sk_position, 64);
    sk_position += 64;

    Ipp8u l            = mldsaCtx->params.l;
    Ipp8u k            = mldsaCtx->params.k;
    Ipp8u eta          = mldsaCtx->params.eta;
    Ipp8u bitlen_2_eta = cp_ml_bitlen(2 * eta);

    for (Ipp8u i = 0; i < l; i++) {
        cp_ml_bitPack(s1 + i, eta, bitlen_2_eta, sk + sk_position + i * 32 * bitlen_2_eta);
    }
    sk_position += l * 32 * bitlen_2_eta;

    for (Ipp8u i = 0; i < k; i++) {
        cp_ml_bitPack(s2 + i, eta, bitlen_2_eta, sk + sk_position + i * 32 * bitlen_2_eta);
    }
    sk_position += k * 32 * bitlen_2_eta;

    Ipp32s value = 1 << (CP_ML_DSA_D - 1);
    for (Ipp8u i = 0; i < k; i++) {
        cp_ml_bitPack(t0 + i,
                      value,
                      cp_ml_bitlen(2 * (Ipp32u)value - 1),
                      sk + sk_position + i * 32 * CP_ML_DSA_D);
    }
}

// Algorithm 25 skDecode(𝑠𝑘)
IPPCP_INLINE void cp_ml_skDecode(const Ipp8u* sk,
                                 Ipp8u* rho,
                                 Ipp8u* K,
                                 Ipp8u* tr,
                                 IppPoly* s1,
                                 IppPoly* s2,
                                 IppPoly* t0,
                                 IppsMLDSAState* mldsaCtx)
{
    Ipp16u sk_position = 0;
    CopyBlock(sk, rho, 32);
    sk_position += 32;

    CopyBlock(sk + sk_position, K, 32);
    sk_position += 32;

    CopyBlock(sk + sk_position, tr, 64);
    sk_position += 64;

    Ipp8u l            = mldsaCtx->params.l;
    Ipp8u k            = mldsaCtx->params.k;
    Ipp8u eta          = mldsaCtx->params.eta;
    Ipp8u bitlen_2_eta = cp_ml_bitlen(2 * eta);

    for (Ipp8u i = 0; i < l; i++) {
        cp_ml_bitUnpack(sk + sk_position + i * 32 * bitlen_2_eta, eta, bitlen_2_eta, s1 + i);
    }
    sk_position += l * 32 * bitlen_2_eta;

    for (Ipp8u i = 0; i < k; i++) {
        cp_ml_bitUnpack(sk + sk_position + i * 32 * bitlen_2_eta, eta, bitlen_2_eta, s2 + i);
    }
    sk_position += k * 32 * bitlen_2_eta;

    Ipp32s value = 1 << (CP_ML_DSA_D - 1);
    for (Ipp8u i = 0; i < k; i++) {
        cp_ml_bitUnpack(sk + sk_position + i * 32 * CP_ML_DSA_D,
                        value,
                        cp_ml_bitlen((Ipp32u)(2 * value - 1)),
                        t0 + i);
    }
}

// Algorithm 26 sigEncode(̃𝐳, 𝐡)
IPPCP_INLINE void cp_ml_sigEncode(const IppPoly* z,
                                  const IppPoly* h,
                                  Ipp8u* sig,
                                  IppsMLDSAState* mldsaCtx)
{
    Ipp8u lambda_4        = mldsaCtx->params.lambda_div_4;
    Ipp8u l               = mldsaCtx->params.l;
    Ipp32s gamma_1        = mldsaCtx->params.gamma_1;
    Ipp8u bitlen_2_gamma1 = cp_ml_bitlen((Ipp32u)(2 * gamma_1 - 1));

    // Encode z
    Ipp8u* pEncodedSig = sig + lambda_4;
    for (Ipp8u i = 0; i < l; i++) {
        cp_ml_bitPack(z + i, gamma_1, bitlen_2_gamma1, pEncodedSig + i * 32 * bitlen_2_gamma1);
    }
    pEncodedSig += l * 32 * bitlen_2_gamma1;

    // Encode h
    cp_ml_hintBitPack(h, mldsaCtx->params.omega, mldsaCtx->params.k, pEncodedSig);
}

// Algorithm 27 sigDecode(𝜎)
IPPCP_INLINE IppStatus cp_ml_sigDecode(const Ipp8u* sig,
                                       IppPoly* z,
                                       IppPoly* h,
                                       IppsMLDSAState* mldsaCtx)
{
    IppStatus sts = ippStsErr;

    Ipp8u lambda_4        = mldsaCtx->params.lambda_div_4;
    Ipp8u l               = mldsaCtx->params.l;
    Ipp32s gamma_1        = mldsaCtx->params.gamma_1;
    Ipp8u bitlen_2_gamma1 = cp_ml_bitlen((Ipp32u)(2 * gamma_1 - 1));

    // Decode z
    const Ipp8u* pEncodedSig = sig + lambda_4;
    for (Ipp8u i = 0; i < l; i++) {
        cp_ml_bitUnpack(pEncodedSig + i * 32 * bitlen_2_gamma1, gamma_1, bitlen_2_gamma1, z + i);
    }
    pEncodedSig += l * 32 * bitlen_2_gamma1;

    // Decode h
    sts = cp_ml_hintBitUnpack(pEncodedSig, mldsaCtx->params.omega, mldsaCtx->params.k, h);

    return sts;
}

// Algorithm 28 w1Encode(𝐰1)
IPPCP_INLINE void cp_ml_w1Encode(const IppPoly* w1, Ipp8u* w1_, IppsMLDSAState* mldsaCtx)
{
    Ipp32s value       = (CP_ML_DSA_Q - 1) / (2 * mldsaCtx->params.gamma_2) - 1;
    const Ipp8u bitlen = cp_ml_bitlen((Ipp32u)value);
    // Encode w1 into w1_
    for (Ipp32u i = 0; i < mldsaCtx->params.k; ++i) {
        cp_ml_simpleBitPack(w1 + i, bitlen, w1_ + i * 32 * bitlen);
    }
}

// =============================================
// 7.4 High-Order and Low-Order Bits and Hints
// =============================================

/*
// Barrett reduction for fixed n = q
//   res = x mod n, where bitsize(x) <= 2*k and bitsize(n) <= k.
//
// Input:  number to be reduced of maximum size 24 bits
// Output: number in Z_{q}
*/

IPPCP_INLINE Ipp32s cp_ml_barrettReduce(Ipp64s x)
{
    const Ipp32s CP_ML_BARRETT_K = 24;
    // b^(2*k) = 2^48
    const Ipp64s CP_ML_BARRETT_B_POW_2xK = ((Ipp64s)1 << (2 * CP_ML_BARRETT_K));
    // Pre-computed mu = floor(b^(2*k)/n)
    const Ipp64s mu = ((Ipp64s)(CP_ML_BARRETT_B_POW_2xK / CP_ML_DSA_Q));
    // 1. t = floor((mu*x)/2^24)
    Ipp64s t = (Ipp64s)((mu * (Ipp64s)x) >> (2 * CP_ML_BARRETT_K));
    // 2. t = floor((mu*x)/2^24) * n
    t = t * CP_ML_DSA_Q;
    // 3. res = x - floor((mu*x)/2^24)*n
    Ipp32s res = (Ipp32s)(x - t);

    // 4. if res >= n then res -= n
    res -= CP_ML_DSA_Q;
    res += (res >> (sizeof(Ipp32s) * 8 - 1)) & CP_ML_DSA_Q;
    res += (res >> (sizeof(Ipp32s) * 8 - 1)) & CP_ML_DSA_Q;

    return res;
}

IPPCP_INLINE Ipp32s cp_ml_montgomeryReduce(Ipp64s a);

// Calculates a mod q with approximation of division by q using shifts: q is ~2^23
IPPCP_INLINE Ipp32s cp_ml_simplifiedBarrettReduce(Ipp32s a)
{
    Ipp64s t = (a + (1 << 22)) >> 23;
    t        = a - t * CP_ML_DSA_Q;
    return (Ipp32s)t;
}

// Algorithm 35 Power2Round(𝑟)
IPPCP_INLINE void cp_ml_power2RoundVector(const IppPoly* r, IppPoly* r0, IppPoly* r1, Ipp32s k)
{
    for (Ipp8u i = 0; i < k; i++) {
        for (Ipp32u j = 0; j < CP_ML_N; j++) {
            Ipp32s r_       = cp_ml_barrettReduce(r[i].values[j]);
            r0[i].values[j] = r_ & ((1 << CP_ML_DSA_D) - 1);
            if (r0[i].values[j] > (1 << (CP_ML_DSA_D - 1))) {
                r0[i].values[j] -= (1 << CP_ML_DSA_D);
            }
            r1[i].values[j] = (r_ - r0[i].values[j]) >> CP_ML_DSA_D;
        }
    }
}

// Algorithm 36 Decompose(𝑟)
IPPCP_INLINE void cp_ml_decompose(Ipp32s r, Ipp32s gamma_2, Ipp32s* r0, Ipp32s* r1)
{
    // Ipp32s r_ = r % CP_ML_DSA_Q;
    Ipp32s r_ = cp_ml_barrettReduce((Ipp64s)r);
    // *r0 = mod_pm_q(r_, 2 * gamma_2);
    Ipp32s gamma_2_2 = (gamma_2 << 1); // gamma_2 == 190464 (ML-DSA-44) or 523776
    // *r0 = r_ % gamma_2_2; for constant execution time
    *r0 = r_ - (r_ / gamma_2_2) * (gamma_2_2);
    if (*r0 > gamma_2) {
        *r0 -= gamma_2_2;
    }

    if (r_ - *r0 == CP_ML_DSA_Q - 1) {
        *r1 = 0;
        *r0 -= 1;
    } else {
        *r1 = (r_ - *r0) / gamma_2_2;
    }
}

// Algorithm 37 HighBits(𝑟)
IPPCP_INLINE void cp_ml_highBitsVector(IppPoly* r, Ipp32s gamma_2, IppPoly* r1, Ipp32s k)
{
    Ipp32s r0;
    for (Ipp8u i = 0; i < k; i++) {
        for (Ipp32u j = 0; j < CP_ML_N; ++j) {
            cp_ml_decompose(r[i].values[j], gamma_2, &r0, &r1[i].values[j]);
        }
    }
}

// Algorithm 38 LowBits(𝑟)
IPPCP_INLINE void cp_ml_lowBits(IppPoly* r, Ipp32s gamma_2, IppPoly* r0)
{
    Ipp32s r1;
    for (Ipp32u j = 0; j < CP_ML_N; ++j) {
        cp_ml_decompose(r->values[j], gamma_2, &r0->values[j], &r1);
    }
}

// Algorithm 39 MakeHint(𝑧, 𝑟)
IPPCP_INLINE Ipp32s cp_ml_makeHint(Ipp32s z, Ipp32s r, Ipp32s gamma_2)
{
    Ipp32s r1, v1, r0;
    // high bits of r
    cp_ml_decompose(r, gamma_2, &r0, &r1);
    // high bits of r + z
    cp_ml_decompose(r + z, gamma_2, &r0, &v1);
    return (r1 != v1) ? 1 : 0;
}

// Algorithm 40 UseHint(h, r)
IPPCP_INLINE void cp_ml_useHintVector(IppPoly* h,
                                      IppPoly* r,
                                      IppPoly* out,
                                      Ipp32s gamma_2,
                                      Ipp32s k)
{
    Ipp32s m = (CP_ML_DSA_Q - 1) / (2 * gamma_2); // m == 44 (ML-DSA-44) or 16 (others 2)
    Ipp32s r0, r1;
    for (Ipp8u i = 0; i < k; i++) {
        for (Ipp32u j = 0; j < CP_ML_N; j++) {
            cp_ml_decompose(r[i].values[j], gamma_2, &r0, &r1);

            if (h[i].values[j] == 1) {
                if (r0 > 0) {
                    r1 = (m == 16 ? (r1 + 1) & 15 : (r1 + 1) % m);
                } else {
                    r1 = (m == 16 ? (r1 - 1) & 15 : (r1 - 1) % m);
                    if (r1 < 0) {
                        r1 += m;
                    }
                }
            }
            out[i].values[j] = r1;
        }
    }
}

// =============================================
// 7.5 NTT and NTT^{-1}
// =============================================

// Algorithm 41 NTT(w)
IPPCP_INLINE void cp_ml_NTT(IppPoly* f)
{
    Ipp32u i = 1;
    for (Ipp8u len = CP_ML_N / 2; len >= 1; len >>= 1) {
        for (Ipp32u start = 0; start < CP_ML_N; start += 2 * len) {
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
}

// Algorithm 42 NTT^−1(w)
IPPCP_INLINE void cp_ml_inverseNTT(IppPoly* w, int addq)
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

    // extra reduce step for montgomery to add q
    if (addq == 1) {
        for (Ipp32u j = 0; j < CP_ML_N; ++j) {
            w->values[j] =
                cp_ml_simplifiedBarrettReduce(w->values[j] + ((w->values[j] >> 31) & CP_ML_DSA_Q));
        }
    }
}

IPPCP_INLINE void cp_ml_NTT_output(const IppPoly* in, IppPoly* out)
{
    for (Ipp32u i = 0; i < CP_ML_N; ++i) {
        out->values[i] = in->values[i];
    }
    cp_ml_NTT(out);
}

// =============================================
// 7.6 Arithmetic Under NTT
// =============================================

// Algorithm 44 AddNTT(𝑎,̂𝑏)
IPPCP_INLINE void cp_ml_addNTT(const IppPoly* a, const IppPoly* b, IppPoly* c)
{
    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        // pC[i] = (pA[i] + pB[i]) % CP_ML_DSA_Q;
        c->values[i] = cp_ml_simplifiedBarrettReduce(a->values[i] + b->values[i]);
    }
}

IPPCP_INLINE void cp_ml_subNTT(const IppPoly* a, const IppPoly* b, IppPoly* c)
{
    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        c->values[i] = cp_ml_simplifiedBarrettReduce(a->values[i] - b->values[i]);
    }
}

IPPCP_INLINE void cp_ml_scalarNTT(const IppPoly* a, IppPoly* b, Ipp32s c)
{
    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        b->values[i] = a->values[i] * c;
    }
}

// Algorithm 45 MultiplyNTT(𝑎,̂𝑏)
IPPCP_INLINE void cp_ml_multiplyNTT(const IppPoly* a, const IppPoly* b, IppPoly* c)
{
    for (Ipp32u i = 0; i < CP_ML_N; i++) {
        c->values[i] = cp_ml_montgomeryReduce((Ipp64s)(a->values[i]) * (b->values[i]));
    }
}

// Algorithm 48 MatrixVectorNTT(𝐌,̂ 𝐯)
IPPCP_INLINE void cp_ml_matrixVectorNTT(IppPoly* M, IppPoly* v, IppPoly* w, Ipp32s l, Ipp32s k)
{
    IppPoly temp;
    for (Ipp32s i = 0; i < k; i++) {
        // w[i] <- 0
        for (Ipp32u idx = 0; idx < CP_ML_N; idx++) {
            w[i].values[idx] = 0;
        }
        for (Ipp32s j = 0; j < l; j++) {
            cp_ml_multiplyNTT(M + (i * l + j), v + j, &temp);
            cp_ml_addNTT(w + i, &temp, w + i);
        }
    }
}

// =============================================
// Appendix A — Montgomery Multiplication
// =============================================

// Algorithm 49 MontgomeryReduce(a)
IPPCP_INLINE Ipp32s cp_ml_montgomeryReduce(Ipp64s a)
{
    Ipp64s q_inv = 58728449; // -q^(-1) mod 2^32

    Ipp32s t = (Ipp32s)(a * q_inv);
    t        = (a - (Ipp64s)t * CP_ML_DSA_Q) >> 32;
    return t;
}

// =============================================
// Out of Spec
// =============================================

// Calculate Infinity norm of polynomial vector: ||poly||
// max_(0≤𝑖<𝑚) (max_(0≤𝑖<256) (|w mod +- q|))
IPPCP_INLINE Ipp32s cp_ml_polyInfinityNormCheck(const IppPoly* poly, Ipp32s size)
{
    Ipp32s norm = 0;
    for (Ipp32s i = 0; i < size; i++) {
        for (Ipp32u j = 0; j < CP_ML_N; j++) {
            Ipp32s val = poly[i].values[j];
            if (val < 0) {
                val = -val;
            }
            if (val > norm) {
                norm = val;
            }
        }
    }
    return norm;
}

// count how much 1 in the memory
IPPCP_INLINE Ipp32s cp_ml_countOnes(const IppPoly* poly, Ipp32s size)
{
    Ipp32s count = 0;
    for (Ipp32s i = 0; i < size; i++) {
        for (Ipp32u j = 0; j < CP_ML_N; j++) {
            count += poly[i].values[j];
        }
    }
    return count;
}

#define cp_ml_sampleInBall OWNAPI(cp_ml_sampleInBall)
IPP_OWN_DECL(IppStatus,
             cp_ml_sampleInBall,
             (const Ipp8u* rho, IppPoly* c, IppsMLDSAState* mldsaCtx))

#if (_IPP32E >= _IPP32E_K0)

#define cp_ml_rejNTTPoly_MB4 OWNAPI(cp_ml_rejNTTPoly_MB4)
IPP_OWN_DECL(IppStatus,
             cp_ml_rejNTTPoly_MB4,
             (Ipp8u * rho1, Ipp8u* rho2, Ipp8u* rho3, Ipp8u* rho4, Ipp32s numBuffers, IppPoly* a))

#define cp_ml_rejBoundedPoly_MB4 OWNAPI(cp_ml_rejBoundedPoly_MB4)
IPP_OWN_DECL(IppStatus,
             cp_ml_rejBoundedPoly_MB4,
             (Ipp8u * rho1,
              Ipp8u* rho2,
              Ipp8u* rho3,
              Ipp8u* rho4,
              Ipp32s numBuffers,
              IppPoly* s,
              IppsMLDSAState* mldsaCtx))

#else

#define cp_ml_rejNTTPoly OWNAPI(cp_ml_rejNTTPoly)
IPP_OWN_DECL(IppStatus, cp_ml_rejNTTPoly, (Ipp8u * rho, IppPoly* a, IppsMLDSAState* mldsaCtx))

#define cp_ml_rejBoundedPoly OWNAPI(cp_ml_rejBoundedPoly)
IPP_OWN_DECL(IppStatus, cp_ml_rejBoundedPoly, (Ipp8u * rho, IppPoly* a, IppsMLDSAState* mldsaCtx))

#endif // (_IPP32E >= _IPP32E_K0)

#define cp_ml_expandA OWNAPI(cp_ml_expandA)
IPP_OWN_DECL(IppStatus,
             cp_ml_expandA,
             (const Ipp8u* rho, IppPoly* matrixA, IppsMLDSAState* mldsaCtx))

#define cp_ml_expandS OWNAPI(cp_ml_expandS)
IPP_OWN_DECL(IppStatus,
             cp_ml_expandS,
             (Ipp8u * rho, IppPoly* s1, IppPoly* s2, IppsMLDSAState* mldsaCtx))

#define cp_ml_expandMask OWNAPI(cp_ml_expandMask)
IPP_OWN_DECL(IppStatus,
             cp_ml_expandMask,
             (Ipp8u * rho, Ipp32u mu, IppPoly* out, IppsMLDSAState* mldsaCtx))

#define cp_ml_expandMatrixMultiplyVectorNTT OWNAPI(cp_ml_expandMatrixMultiplyVectorNTT)
IPP_OWN_DECL(IppStatus,
             cp_ml_expandMatrixMultiplyVectorNTT,
             (const Ipp8u* rho, IppPoly* v, IppPoly* out, IppsMLDSAState* mldsaCtx))

// =============================================
// 6. Internal functions (keygen, sign, verify)
// =============================================

#define cp_MLDSA_keyGen_internal OWNAPI(cp_MLDSA_keyGen_internal)
IPP_OWN_DECL(IppStatus,
             cp_MLDSA_keyGen_internal,
             (const Ipp8u* ksi, Ipp8u* pk, Ipp8u* sk, IppsMLDSAState* mldsaCtx))

#define cp_MLDSA_Sign_internal OWNAPI(cp_MLDSA_Sign_internal)
IPP_OWN_DECL(IppStatus,
             cp_MLDSA_Sign_internal,
             (const Ipp8u* M,
              Ipp32s msg_size,
              const Ipp8u* ctx,
              Ipp32s ctx_size,
              const Ipp8u* sk,
              Ipp8u* rnd,
              Ipp8u* sig,
              IppsMLDSAState* mldsaCtx))

#define cp_MLDSA_Verify_internal OWNAPI(cp_MLDSA_Verify_internal)
IPP_OWN_DECL(IppStatus,
             cp_MLDSA_Verify_internal,
             (const Ipp8u* M,
              Ipp32s msg_size,
              const Ipp8u* ctx,
              Ipp32s ctx_size,
              const Ipp8u* pk,
              const Ipp8u* sig,
              Ipp32s* is_valid,
              IppsMLDSAState* mldsaCtx))

#endif // #ifndef _IPPCP_ML_DSA_H_
