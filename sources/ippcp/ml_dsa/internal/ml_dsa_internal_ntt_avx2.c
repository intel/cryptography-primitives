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

/*-
 ******************************************************************************
 * ML-DSA AVX2 Vectorized NTT/INTT Routines
 *
 * Description:
 *   This file provides optimized x86_64 implementations of the Number
 *   Theoretic Transform (NTT) and inverse NTT (INTT) and their modular
 *   Montgomery reduction building blocks for the ML-DSA signature scheme.
 *
 *   The routines are vectorized using AVX2 intrinsics, performing modular
 *   arithmetic and butterfly operations on multiple coefficients in
 *   parallel. The mathematical structure and transformations strictly follow
 *   those implemented in the corresponding generic C code
 *   (ml_dsa_internal_ntt.c), ensuring that this file provides a drop-in,
 *   performant backend using the same algorithms and data layout.  There are
 *   dedicated zeta tables, zetas_inverse and zetas_montgomery. They are
 *   essentially reformatted original tables from zeta.h file to reduce INTT
 *   compute cycles.
 *
 *   This module supports both the forward (NTT) and inverse (INTT) polynomial
 *   transforms, as well as element-wise NTT-domain polynomial multiplication,
 *   compatible with the ML-DSA cryptographic protocol.
 *
 *   Step, offset and zeta index details provided for NTT and INTT level
 *   operations correspond directly to the original C implementations from
 *   ml_dsa_internal_ntt.c file.
 *
 * Notes:
 *   - Uses AVX2 intrinsics and 256-bit vectors that accommodate 8 32-bit coefficients
 *   - Must be kept functionally synchronized with the math and interface of
 *     ml_dsa_internal_ntt.c
 *   - Data structures, twiddle factors ("zetas"), and constants must match
 *     those in the C implementation
 ******************************************************************************
 */

#include "owndefs.h"
#include "ippcpdefs.h"
#include "stateless_pqc/ml_dsa/ml_dsa.h"
#include "stateless_pqc/common.h"
#include "stateless_pqc/zetas.h"
#include <immintrin.h>


#if (_IPP32E >= _IPP32E_L9)

#define VEC_Q                        _mm256_set1_epi32(CP_ML_DSA_Q)
#define ML_DSA_DEGREE_INV_MONTGOMERY 41978      /* Inverse of 256 mod q, in Montgomery form. */
#define ML_DSA_Q_NEG_INV             4236238847 /* Inverse of -q modulo 2^32 */
#define VEC_Q_NEG_INV                _mm256_set1_epi64x((long long)ML_DSA_Q_NEG_INV) /* -Q^{-1} mod 2^32 */

/* Duplicate the high dword of each qword over the low one (vmovshdup) */
IPPCP_INLINE __m256i movshdup_x8(__m256i a)
{
    return _mm256_castps_si256(_mm256_movehdup_ps(_mm256_castsi256_ps(a)));
}

/* Select dwords from two vectors as vshufps does */
#define shufps_x8(a, b, imm) \
    _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(a), _mm256_castsi256_ps(b), (imm)))

/*
 * Reduce 8 packed 32-bit values that can be between Q and 2Q back into
 * [0, Q) (vpcmpgtd + vpandn + vpsubd in the assembly version).
 */

IPPCP_INLINE __m256i reduce_once_x8(__m256i a)
{
    __m256i mask = _mm256_cmpgt_epi32(VEC_Q, a); /* mask = Q > a ? ~0 : 0 */

    /* a -= (a >= Q) ? Q : 0 */
    return _mm256_sub_epi32(a, _mm256_andnot_si256(mask, VEC_Q));
}

/*-
 ******************************************************************************
 * canonicalize_x8
 *
 * Description:
 *   Brings 8 packed signed 32-bit coefficients into [0, Q).
 *
 *   Both the NTT and the INTT levels below require their input in [0, Q): the
 *   butterflies multiply coefficients with vpmuludq (see
 *   multiply_mod_q_split()), which would read a negative coefficient as
 *   coeff + 2^32, and reduce_once_x8() only ever subtracts a single Q, so it
 *   cannot lift a negative value back into range either. cp_ml_NTT() is called
 *   on s1, s2, t0, y, c and z and cp_ml_inverseNTT() on the output of
 *   cp_ml_multiplyNTT() / cp_ml_addNTT() / cp_ml_subNTT(), all of which hold
 *   negative coefficients, so the input is canonicalized first.
 *
 *   This is the vector form of cp_ml_simplifiedBarrettReduce() followed by a
 *   conditional add of Q. Writing a = t x 2^23 + e, the shift below gives
 *   e in [-2^22, 2^22), so the Barrett step leaves
 *       a - t x Q = t x (2^23 - Q) + e = t x 8191 + e
 *   which for |t| <= 256 is bounded by 256 x 8191 + 2^22 = 6291200 < Q. One
 *   conditional add is therefore enough; no second reduction is needed.
 *
 * Parameters:
 *   a - 8 signed coefficients, anywhere in [INT32_MIN, 2^31 - 2^22), i.e.
 *       about +-256Q - far wider than any caller needs
 *
 * Returns:
 *   The same 8 values mod Q, each in [0, Q)
 ******************************************************************************
 */
IPPCP_INLINE __m256i canonicalize_x8(__m256i a)
{
    /* t = (a + 2^22) >> 23 - the approximate quotient a / Q, |t| <= 256 */
    __m256i t = _mm256_srai_epi32(_mm256_add_epi32(a, _mm256_set1_epi32(1 << 22)), 23);

    /* a -= t x Q - lands in (-Q, Q); t x Q <= 256Q < 2^31, so vpmulld is exact */
    a = _mm256_sub_epi32(a, _mm256_mullo_epi32(t, VEC_Q));

    /* a += (a < 0) ? Q : 0 */
    return _mm256_add_epi32(a, _mm256_and_si256(_mm256_srai_epi32(a, 31), VEC_Q));
}

/*-
 ******************************************************************************
 * center_x8
 *
 * Description:
 *   Rewrites 8 packed coefficients that are already in [0, Q) as the centered
 *   representatives that cp_ml_polyInfinityNormCheck() expects, i.e. the
 *   vector form of the cp_ml_inverseNTT() "addq" tail
 *
 *       cp_ml_simplifiedBarrettReduce(a + ((a >> 31) & Q))
 *
 *   for a non-negative a. The conditional add of Q is then a no-op, and the
 *   Barrett step reduces to a single conditional subtract: with a in [0, Q),
 *   t = (a + 2^22) >> 23 is 1 exactly when a >= 2^22 and 0 otherwise, so
 *   a - t x Q is bit-for-bit what the scalar tail produces.
 *
 * Parameters:
 *   a - 8 coefficients, each in [0, Q)
 *
 * Returns:
 *   The same 8 values mod Q, each in (-Q + 2^22, 2^22)
 ******************************************************************************
 */
IPPCP_INLINE __m256i center_x8(__m256i a)
{
    /* mask = a >= 2^22 ? ~0 : 0 */
    __m256i mask = _mm256_cmpgt_epi32(a, _mm256_set1_epi32((1 << 22) - 1));

    /* a -= (a >= 2^22) ? Q : 0 */
    return _mm256_sub_epi32(a, _mm256_and_si256(mask, VEC_Q));
}

/*-
 ******************************************************************************
 * multiply_mod_q
 *
 * Description:
 *   The inputs (A and B) are 256-bit vectors, where each packs 8 32-bit
 *   integers. The result, (A * B mod Q), is also a 256-bit vector.
 *   This routine is used as the core modular multiplication step in
 *   NTT butterfly operations.
 *
 * Parameters:
 *   in_a     - Input vector containing 8 32-bit unsigned values (A)
 *   b_even   - Input vector supplying B for the even indexes of A
 *   b_odd    - Input vector supplying B for the odd indexes of A. When the
 *              zetas are uniform across each qword of B (each qword formed by
 *              repeating its low dword, DW|DW) this is B itself, avoiding the
 *              need for a vmovshdup - see multiply_mod_q_bcast32().
 *
 * Returns:
 *   The resulting 8 packed 32-bit integers, each (A * B) mod Q
 ******************************************************************************
 */
IPPCP_INLINE __m256i multiply_mod_q_split(__m256i in_a, __m256i b_even, __m256i b_odd)
{
    __m256i t0, t1, t2, out;

    /* Multiply A x B */
    t0 = _mm256_mul_epu32(in_a, b_even);             /* even indexes */
    t1 = _mm256_mul_epu32(movshdup_x8(in_a), b_odd); /* odd indexes */

    /* Montgomery reduction: t1 = (A x B)[31..0] x Qinv */
    out = _mm256_mul_epu32(VEC_Q_NEG_INV, t0);
    t2  = _mm256_mul_epu32(VEC_Q_NEG_INV, t1);

    /* t2 = t1[31..0] x Q */
    out = _mm256_mul_epu32(out, VEC_Q);
    t2  = _mm256_mul_epu32(t2, VEC_Q);

    /* t3 = (A x B) + t2 */
    out = _mm256_add_epi64(out, t0);
    t1  = _mm256_add_epi64(t2, t1);

    /* out = t3 >> 32 */
    out = movshdup_x8(out);
    out = _mm256_blend_epi32(out, t1, 0xAA);

    /* out can be between Q and 2Q, do final reduction */
    return reduce_once_x8(out);
}

/* (A x B) mod Q where every dword of B is significant */
IPPCP_INLINE __m256i multiply_mod_q(__m256i in_a, __m256i in_b)
{
    return multiply_mod_q_split(in_a, in_b, movshdup_x8(in_b));
}

/* (A x B) mod Q where each qword of B repeats its low dword (DW|DW) */
IPPCP_INLINE __m256i multiply_mod_q_bcast32(__m256i in_a, __m256i in_b)
{
    return multiply_mod_q_split(in_a, in_b, in_b);
}

/*
 * (A x B) mod Q where the dwords of A and B are *signed*. Unlike the NTT /
 * INTT levels below, the pointwise multiply is fed by cp_ml_NTT(), which
 * leaves its output unreduced within about +-4Q, so vpmuldq is needed here -
 * vpmuludq would read the negative coefficients as huge unsigned values,
 * which is wrong mod Q, not just a different representative.
 *
 * The Montgomery reduction is unchanged: only the low dword of (A x B) feeds
 * it, and that is signedness independent. Its result lands in (-Q, 2Q) as
 * long as |A x B| < Q x 2^31 (satisfied with room to spare for |A|,|B| < 16Q),
 * so the negative lanes are lifted by Q before the usual reduce_once_x8().
 * The output is in [0, Q) - congruent to, but not bitwise equal to, the
 * signed representative that cp_ml_montgomeryReduce() returns.
 */
IPPCP_INLINE __m256i multiply_mod_q_signed(__m256i in_a, __m256i in_b)
{
    __m256i t0, t1, t2, out;

    /* Multiply A x B (vpmuldq) */
    t0 = _mm256_mul_epi32(in_a, in_b);                           /* even indexes */
    t1 = _mm256_mul_epi32(movshdup_x8(in_a), movshdup_x8(in_b)); /* odd indexes */

    /* Montgomery reduction: m = (A x B)[31..0] x Qinv */
    out = _mm256_mul_epu32(VEC_Q_NEG_INV, t0);
    t2  = _mm256_mul_epu32(VEC_Q_NEG_INV, t1);

    /* m[31..0] x Q */
    out = _mm256_mul_epu32(out, VEC_Q);
    t2  = _mm256_mul_epu32(t2, VEC_Q);

    /* (A x B) + m[31..0] x Q - the low 32 bits cancel */
    out = _mm256_add_epi64(out, t0);
    t1  = _mm256_add_epi64(t2, t1);

    /* out = <the above> >> 32 - the qword sums stay well inside 64 bits, so
     * their high dword is the arithmetic shift */
    out = movshdup_x8(out);
    out = _mm256_blend_epi32(out, t1, 0xAA);

    /* out is in (-Q, 2Q): lift the negative lanes, then reduce the [Q, 2Q) ones */
    out = _mm256_add_epi32(out, _mm256_and_si256(_mm256_srai_epi32(out, 31), VEC_Q));
    return reduce_once_x8(out);
}

/* Load / store 8 coefficients (vmovdqu) */
IPPCP_INLINE __m256i load_x8(const Ipp32s* p) { return _mm256_loadu_si256((const __m256i*)p); }

IPPCP_INLINE void store_x8(Ipp32s* p, __m256i a) { _mm256_storeu_si256((__m256i*)p, a); }

/* Broadcast a single zeta over all 8 dwords (vpbroadcastd) */
IPPCP_INLINE __m256i bcast_zeta(const Ipp32s* zeta) { return _mm256_set1_epi32((int)*zeta); }

/*
 * Load 2 zetas, the first one into the low 128-bit lane and the second one
 * into the high lane (vpbroadcastd x2 + vpblendd)
 */
IPPCP_INLINE __m256i bcast_zeta_x2(const Ipp32s* zetas)
{
    return _mm256_blend_epi32(bcast_zeta(&zetas[0]), bcast_zeta(&zetas[1]), 0xf0);
}

/*
 * Load 4 zetas into the low dword of each qword (vmovdqu + vpmovzxdq).
 * It is enough that the 1st dword of each qword is populated.
 */
IPPCP_INLINE __m256i load_zeta_x4(const Ipp32s* zetas)
{
    return _mm256_cvtepu32_epi64(_mm_loadu_si128((const __m128i*)zetas));
}

/*-
 ******************************************************************************
 ***
 *** NTT (Number Theoretic Transform)
 ***
 ******************************************************************************
 */

/*-
 ******************************************************************************
 * ntt_butterfly
 *
 * Description:
 *   Performs the butterfly operation for a single NTT stage on two input
 *   vectors, applying a twiddle factor ("zetas"). This is the core step in
 *   NTT layers:
 *     - Computes t_odd = w_odd * zetas mod Q (Montgomery form)
 *     - n_even = w_even + t_odd mod Q
 *     - n_odd  = (w_even + Q) - t_odd mod Q
 *   Processes 8 coefficients at a time.
 *
 * Parameters:
 *   w_even  - vector containing the "even" values
 *   w_odd   - vector containing the "odd" values
 *   zetas   - vector containing the twiddle factor(s)
 *   n_even  - Output vector for the updated even coefficients
 *   n_odd   - Output vector for the updated odd coefficients
 *
 * Output:
 *   n_even  - Updated even coefficients after butterfly and reduction
 *   n_odd   - Updated odd coefficients after butterfly and reduction
 *
 * Notes:
 *   - ntt_butterfly() is used by levels 0 to 6, where the same zeta dwords
 *     are repeated within each qword. ntt_butterfly_zeta_x8() is used by
 *     level 7, where each zeta dword is different.
 *   - n_even / n_odd may point at the inputs of this call
 ******************************************************************************
 */
IPPCP_INLINE void ntt_butterfly_t_odd(__m256i w_even,
                                      __m256i t_odd,
                                      __m256i* n_even,
                                      __m256i* n_odd)
{
    __m256i even, odd;

    /* compute new w_odd (n_odd): (w_even + Q) - t_odd */
    odd = _mm256_sub_epi32(_mm256_add_epi32(w_even, VEC_Q), t_odd);

    /* compute new w_even (n_even): w_even + t_odd */
    even = _mm256_add_epi32(w_even, t_odd);

    /* reduce n_even & n_odd - results can be between Q and 2Q */
    *n_even = reduce_once_x8(even);
    *n_odd  = reduce_once_x8(odd);
}

/* levels 0 to 6: same zeta dwords within each qword */
IPPCP_INLINE void ntt_butterfly(__m256i w_even,
                                __m256i w_odd,
                                __m256i zetas,
                                __m256i* n_even,
                                __m256i* n_odd)
{
    ntt_butterfly_t_odd(w_even, multiply_mod_q_bcast32(w_odd, zetas), n_even, n_odd);
}

/* level 7: each zeta dword is different */
IPPCP_INLINE void ntt_butterfly_zeta_x8(__m256i w_even,
                                        __m256i w_odd,
                                        __m256i zetas,
                                        __m256i* n_even,
                                        __m256i* n_odd)
{
    ntt_butterfly_t_odd(w_even, multiply_mod_q(w_odd, zetas), n_even, n_odd);
}

/*-
 ******************************************************************************
 * ntt_levels0to2
 *
 * Description: Performs the first three layers (levels 0, 1, and 2) of the NTT.
 *   It works on 8 vectors, 8 32-bit coefficients each. Coefficients loaded into
 *   the vectors are separated by 32 coefficients (32 x 4 bytes = 128 bytes).
 *   All 8 vectors undergo consecutive butterfly operations with the appropriate
 *   "zetas" (twiddle factors) for each level. This function must be called 4
 *   times with different offsets to process all 256 coefficients.
 *
 * Layer/level details:
 *   - Level 0:  offset = 128, step = 1, uses zeta index 1
 *   - Level 1:  offset =  64, step = 2, uses zeta indexes 2, 3
 *   - Level 2:  offset =  32, step = 4, uses zeta indexes 4, 5, 6, 7
 *
 * Arguments:
 *   c       - pointer to the first of a group of 8 coefficients
 *             valid values: p_coeffs + 0, 8, 16 or 24
 *   zetas   - pointer to the zetas (twiddle factors) table
 *
 * Output:
 *   In-place NTT updated coefficients in memory.
 *
 * Notes:
 *   - Must be invoked 4 times for complete polynomial: offsets 0, 8, 16, 24
 ******************************************************************************
 */
IPPCP_INLINE void ntt_levels0to2(Ipp32s* c, const Ipp32s* zetas)
{
    __m256i w0, w1, w2, w3, w4, w5, w6, w7, z;

    w0 = load_x8(c + 0);
    w1 = load_x8(c + 32);
    w2 = load_x8(c + 64);
    w3 = load_x8(c + 96);
    w4 = load_x8(c + 128);
    w5 = load_x8(c + 160);
    w6 = load_x8(c + 192);
    w7 = load_x8(c + 224);

    /*
     * ==============================================================
     * level 0: offset = 128, step = 1
     * zeta indexes = 1
     */
    z = bcast_zeta(&zetas[1]);
    ntt_butterfly(w0, w4, z, &w0, &w4);
    ntt_butterfly(w1, w5, z, &w1, &w5);
    ntt_butterfly(w2, w6, z, &w2, &w6);
    ntt_butterfly(w3, w7, z, &w3, &w7);

    /*
     * ==============================================================
     * level 1: offset = 64, step = 2
     * zeta indexes = 2, 3
     */
    z = bcast_zeta(&zetas[2]);
    ntt_butterfly(w0, w2, z, &w0, &w2);
    ntt_butterfly(w1, w3, z, &w1, &w3);

    z = bcast_zeta(&zetas[3]);
    ntt_butterfly(w4, w6, z, &w4, &w6);
    ntt_butterfly(w5, w7, z, &w5, &w7);

    /*
     * ==============================================================
     * level 2: offset = 32, step = 4
     * zeta indexes = 4, 5, 6, 7
     */
    z = bcast_zeta(&zetas[4]);
    ntt_butterfly(w0, w1, z, &w0, &w1);

    z = bcast_zeta(&zetas[5]);
    ntt_butterfly(w2, w3, z, &w2, &w3);

    z = bcast_zeta(&zetas[6]);
    ntt_butterfly(w4, w5, z, &w4, &w5);

    z = bcast_zeta(&zetas[7]);
    ntt_butterfly(w6, w7, z, &w6, &w7);

    store_x8(c + 0, w0);
    store_x8(c + 32, w1);
    store_x8(c + 64, w2);
    store_x8(c + 96, w3);
    store_x8(c + 128, w4);
    store_x8(c + 160, w5);
    store_x8(c + 192, w6);
    store_x8(c + 224, w7);
}

/*-
 ******************************************************************************
 * ntt_levels3to7
 *
 * Description:
 *   Performs layers 3 through 7 of the NTT on 64 coefficients.
 *
 *   It operates on 8 vectors, each packing 8 32-bit coefficients (64 in
 *   total). Contiguous coefficients are loaded into the vectors (no gap
 *   between them).
 *
 *   The function must be called 4 times to process 256 coefficients. At each
 *   level, the function executes butterfly operations in the correct
 *   coefficient pattern and applies the corresponding twiddle factors
 *   ("zetas").
 *
 * Layer/level details:
 *   - Level 3: offset = 16, step = 8;   zeta indexes 8...15
 *   - Level 4: offset =  8, step = 16;  zeta indexes 16...31
 *   - Level 5: offset =  4, step = 32;  zeta indexes 32...63
 *   - Level 6: offset =  2, step = 64;  zeta indexes 64...127
 *   - Level 7: offset =  1, step = 128; zeta indexes 128...255
 *
 * Arguments:
 *   c                  - pointer to the first of a set of 64 coefficients
 *   z3, z4, z5, z6, z7 - pointers to the required zetas in the table, for
 *                        levels 3 to 7
 *
 * Output:
 *   In-place NTT-transformed coefficients for the selected group.
 *
 * Notes:
 *   - Should be called 4 times per complete 256-coefficient transform
 *     (offsets 0, 64, 128, 192).
 *   - All butterfly operations and twiddle applications are handled by
 *     ntt_butterfly() / ntt_butterfly_zeta_x8().
 ******************************************************************************
 */
IPPCP_INLINE void ntt_levels3to7(Ipp32s* c,
                                 const Ipp32s* z3,
                                 const Ipp32s* z4,
                                 const Ipp32s* z5,
                                 const Ipp32s* z6,
                                 const Ipp32s* z7)
{
    __m256i w0, w1, w2, w3, w4, w5, w6, w7, t0, t1, z;

    /*
     * ==============================================================
     * level 3: offset = 16, step = 8
     * zeta indexes = 8, 9, 10, 11, 12, 13, 14, 15
     */

    /* broadcast zetas */
    z = bcast_zeta(&z3[0]); /* zeta for coefficients 0-15 */

    /* load w_even and w_odd */
    w0 = load_x8(c + 0);  /* w_even[0:7] */
    w1 = load_x8(c + 8);  /* w_even[8:15] */
    w2 = load_x8(c + 16); /* w_odd[0:7] */
    w3 = load_x8(c + 24); /* w_odd[8:15] */

    /* Process first 16 coefficients with zeta in z */
    ntt_butterfly(w0, w2, z, &w0, &w2);
    ntt_butterfly(w1, w3, z, &w1, &w3);

    /* broadcast zetas */
    z = bcast_zeta(&z3[1]); /* zeta for coefficients 16-31 */

    /* load w_even and w_odd */
    w4 = load_x8(c + 32); /* w_even[16:23] */
    w5 = load_x8(c + 40); /* w_even[24:31] */
    w6 = load_x8(c + 48); /* w_odd[16:23] */
    w7 = load_x8(c + 56); /* w_odd[24:31] */

    /* Process next 16 coefficients with zeta in z */
    ntt_butterfly(w4, w6, z, &w4, &w6);
    ntt_butterfly(w5, w7, z, &w5, &w7);

    /*-
     * ==============================================================
     * level 4: offset = 8, step = 16
     * zeta indexes = 16, 17, 18, ..., 30, 31
     *
     * Input dword layout:
     *   w0 = [ 0  1  2  3 |  4  5  6  7] (even)
     *   w1 = [ 8  9 10 11 | 12 13 14 15] (even)
     *   w2 = [16 17 18 19 | 20 21 22 23] (odd)
     *   w3 = [24 25 26 27 | 28 29 30 31] (odd)
     * Required dword layout is the same:
     *   w0 = [ 0  1  2  3 |  4  5  6  7] (even)
     *   w1 = [ 8  9 10 11 | 12 13 14 15] (odd)
     *   w2 = [16 17 18 19 | 20 21 22 23] (even)
     *   w3 = [24 25 26 27 | 28 29 30 31] (odd)
     */

    /* broadcast zetas for first 8 coefficients */
    z = bcast_zeta(&z4[0]); /* zeta for coefficients 0-7 */
    ntt_butterfly(w0, w1, z, &w0, &w1);

    /* broadcast zetas for next 8 coefficients */
    z = bcast_zeta(&z4[1]); /* zeta for coefficients 8-15 */
    ntt_butterfly(w2, w3, z, &w2, &w3);

    /* broadcast zetas for next 8 coefficients */
    z = bcast_zeta(&z4[2]); /* zeta for coefficients 16-23 */
    ntt_butterfly(w4, w5, z, &w4, &w5);

    /* broadcast zetas for next 8 coefficients */
    z = bcast_zeta(&z4[3]); /* zeta for coefficients 24-31 */
    ntt_butterfly(w6, w7, z, &w6, &w7);

    /*-
     * ==============================================================
     * level 5: offset = 4, step = 32
     * zeta indexes = 32, 33, 34, ..., 62, 63
     *
     * prepare w_even and w_odd
     * Input dword layout:
     *   w0 = [ 0  1  2  3 |  4  5  6  7] (even)
     *   w1 = [ 8  9 10 11 | 12 13 14 15] (odd)
     * Required dword layout:
     *   t0 = [ 0  1  2  3 |  8  9 10 11] (even)
     *   w1 = [ 4  5  6  7 | 12 13 14 15] (odd)
     */
    t0 = _mm256_permute2x128_si256(w0, w1, 0x20);
    w1 = _mm256_permute2x128_si256(w0, w1, 0x31);

    /* load zetas for first 8 coefficients (0-3 and 4-7) */
    z = bcast_zeta_x2(&z5[0]);
    ntt_butterfly(t0, w1, z, &w0, &w1);

    /* prepare w_even and w_odd */
    t0 = _mm256_permute2x128_si256(w2, w3, 0x20);
    w3 = _mm256_permute2x128_si256(w2, w3, 0x31);

    /* load zetas for next 8 coefficients (8-11 and 12-15) */
    z = bcast_zeta_x2(&z5[2]);
    ntt_butterfly(t0, w3, z, &w2, &w3);

    /* prepare w_even and w_odd */
    t0 = _mm256_permute2x128_si256(w4, w5, 0x20);
    w5 = _mm256_permute2x128_si256(w4, w5, 0x31);

    /* load zetas for next 8 coefficients (16-19 and 20-23) */
    z = bcast_zeta_x2(&z5[4]);
    ntt_butterfly(t0, w5, z, &w4, &w5);

    /* prepare w_even and w_odd */
    t0 = _mm256_permute2x128_si256(w6, w7, 0x20);
    w7 = _mm256_permute2x128_si256(w6, w7, 0x31);

    /* load zetas for next 8 coefficients (24-27 and 28-31) */
    z = bcast_zeta_x2(&z5[6]);
    ntt_butterfly(t0, w7, z, &w6, &w7);

    /*-
     * ==============================================================
     * level 6: offset = 2, step = 64
     * zeta indexes = 64, 65, 66, ..., 126, 127
     *
     * Input DWORD layout in memory:
     *   w0 = [ 0  1  2  3] [ 8  9 10 11] (even)
     *   w1 = [ 4  5  6  7] [12 13 14 15] (odd)
     *   w2 = [16 17 18 19] [24 25 26 27] (even)
     *   w3 = [20 21 22 23] [28 29 30 31] (odd)
     * Desired DWORD layout:
     *   t0 = [ 0  1  4  5] [ 8  9 12 13] (even)
     *   w1 = [ 2  3  6  7] [10 11 14 15] (odd)
     */

    /* load & prepare zetas */
    z = load_zeta_x4(&z6[0]);

    /* prepare w_even and w_odd */
    t0 = _mm256_unpacklo_epi64(w0, w1);
    w1 = _mm256_unpackhi_epi64(w0, w1);
    ntt_butterfly(t0, w1, z, &w0, &w1);

    /* load & prepare zetas */
    z = load_zeta_x4(&z6[4]);

    /* prepare w_even and w_odd */
    t0 = _mm256_unpacklo_epi64(w2, w3);
    w3 = _mm256_unpackhi_epi64(w2, w3);
    ntt_butterfly(t0, w3, z, &w2, &w3);

    /* load & prepare zetas */
    z = load_zeta_x4(&z6[8]);

    /* prepare w_even and w_odd */
    t0 = _mm256_unpacklo_epi64(w4, w5);
    w5 = _mm256_unpackhi_epi64(w4, w5);
    ntt_butterfly(t0, w5, z, &w4, &w5);

    /* load & prepare zetas */
    z = load_zeta_x4(&z6[12]);

    /* prepare w_even and w_odd */
    t0 = _mm256_unpacklo_epi64(w6, w7);
    w7 = _mm256_unpackhi_epi64(w6, w7);
    ntt_butterfly(t0, w7, z, &w6, &w7);

    /*-
     * ==============================================================
     * level 7: offset = 1, step = 128
     * zeta indexes = 128, 129, 130, ..., 254, 255
     *
     * Input DWORD layout:
     *   w0 = [ 0  1  4  5] [ 8  9 12 13]
     *   w1 = [ 2  3  6  7] [10 11 14 15]
     * Required DWORD layout:
     *   w0 = [ 0  2  4  6] [ 8 10 12 14] (even)
     *   w1 = [ 1  3  5  7] [ 9 11 13 15] (odd)
     */
    t0 = _mm256_unpacklo_epi32(w0, w1); /* t0 = [0 2 1 3] [ 8 10  9 11] */
    t1 = _mm256_unpackhi_epi32(w0, w1); /* t1 = [4 6 5 7] [12 14 13 15] */

    w1 = shufps_x8(t0, t1, 0xEE);       /* w1 = [1 3 5 7] [ 9 11 13 15] */
    w0 = shufps_x8(t0, t1, 0x44);       /* w0 = [0 2 4 6] [ 8 10 12 14] */

    /* load zetas */
    z = load_x8(&z7[0]); /* 8 zetas for coefficients 0-7 */
    ntt_butterfly_zeta_x8(w0, w1, z, &w0, &w1);

    /* load zetas */
    z = load_x8(&z7[8]); /* 8 zetas for coefficients 8-15 */

    /* format w_even and w_odd */
    t0 = _mm256_unpacklo_epi32(w2, w3);
    t1 = _mm256_unpackhi_epi32(w2, w3);

    w3 = shufps_x8(t0, t1, 0xEE);
    w2 = shufps_x8(t0, t1, 0x44);
    ntt_butterfly_zeta_x8(w2, w3, z, &w2, &w3);

    /* load zetas */
    z = load_x8(&z7[16]); /* 8 zetas for coefficients 16-23 */

    /* format w_even and w_odd */
    t0 = _mm256_unpacklo_epi32(w4, w5);
    t1 = _mm256_unpackhi_epi32(w4, w5);

    w5 = shufps_x8(t0, t1, 0xEE);
    w4 = shufps_x8(t0, t1, 0x44);
    ntt_butterfly_zeta_x8(w4, w5, z, &w4, &w5);

    /* load zetas */
    z = load_x8(&z7[24]); /* 8 zetas for coefficients 24-31 */

    /* format w_even and w_odd */
    t0 = _mm256_unpacklo_epi32(w6, w7);
    t1 = _mm256_unpackhi_epi32(w6, w7);

    w7 = shufps_x8(t0, t1, 0xEE);
    w6 = shufps_x8(t0, t1, 0x44);
    ntt_butterfly_zeta_x8(w6, w7, z, &w6, &w7);

    /* Interleave and store first 16 */
    t0 = _mm256_unpacklo_epi32(w0, w1);
    t1 = _mm256_unpackhi_epi32(w0, w1);
    store_x8(c + 0, _mm256_permute2x128_si256(t0, t1, 0x20));
    store_x8(c + 8, _mm256_permute2x128_si256(t0, t1, 0x31));

    t0 = _mm256_unpacklo_epi32(w2, w3);
    t1 = _mm256_unpackhi_epi32(w2, w3);
    store_x8(c + 16, _mm256_permute2x128_si256(t0, t1, 0x20));
    store_x8(c + 24, _mm256_permute2x128_si256(t0, t1, 0x31));

    /* Interleave and store second 16 */
    t0 = _mm256_unpacklo_epi32(w4, w5);
    t1 = _mm256_unpackhi_epi32(w4, w5);
    store_x8(c + 32, _mm256_permute2x128_si256(t0, t1, 0x20));
    store_x8(c + 40, _mm256_permute2x128_si256(t0, t1, 0x31));

    t0 = _mm256_unpacklo_epi32(w6, w7);
    t1 = _mm256_unpackhi_epi32(w6, w7);
    store_x8(c + 48, _mm256_permute2x128_si256(t0, t1, 0x20));
    store_x8(c + 56, _mm256_permute2x128_si256(t0, t1, 0x31));
}

/*-
 ******************************************************************************
 ***
 *** INTT (Inverse Number Theoretic Transform)
 ***
 ******************************************************************************
 */

/*-
 ******************************************************************************
 * intt_butterfly
 *
 * Description:
 *   Performs the butterfly operation for a single stage of the INTT
 *   on two 8-element vectors of 32-bit integers.
 *
 *   Implements the core data-mixing and modular multiplication steps with a
 *   zeta (twiddle factor), including the modular reductions. The updated even
 *   and odd results are put into the designated outputs.
 *
 *   This butterfly operation computes:
 *     n_even = (w_even + w_odd) mod Q
 *     n_odd  = ((w_even + Q) - w_odd) * zetas mod Q
 *   where Q is the NTT modulus, and zetas is the power of a primitive root
 *   used for this stage.
 *
 * Parameters:
 *   w_even    - vector with "even" input coefficients
 *   w_odd     - vector with "odd" input coefficients
 *   zetas     - vector with modular twiddle factors for this butterfly
 *   n_even    - Output vector for new even coefficients
 *   n_odd     - Output vector for new odd coefficients
 *
 * Output:
 *   n_even, n_odd
 *
 * Notes:
 *   - intt_butterfly_zeta_x8() is used by level 0, where each zeta dword is
 *     different. intt_butterfly() is used by levels 1 to 7, where the same
 *     zeta dwords are repeated within each qword.
 *   - n_even / n_odd may point at the inputs of this call
 ******************************************************************************
 */
IPPCP_INLINE void intt_butterfly_prepare(__m256i w_even,
                                         __m256i w_odd,
                                         __m256i* n_even,
                                         __m256i* n_odd)
{
    /* n_even = reduce_once(w_even + w_odd) */
    *n_even = reduce_once_x8(_mm256_add_epi32(w_even, w_odd));

    /* n_odd = (w_even + Q) - w_odd */
    *n_odd = _mm256_sub_epi32(_mm256_add_epi32(w_even, VEC_Q), w_odd);
}

/* levels 1 to 7: same zeta dwords within each qword */
IPPCP_INLINE void intt_butterfly(__m256i w_even,
                                 __m256i w_odd,
                                 __m256i zetas,
                                 __m256i* n_even,
                                 __m256i* n_odd)
{
    __m256i odd;

    intt_butterfly_prepare(w_even, w_odd, n_even, &odd);

    /* Multiply n_odd by zetas (step root) */
    *n_odd = multiply_mod_q_bcast32(odd, zetas);
}

/* level 0: each zeta dword is different */
IPPCP_INLINE void intt_butterfly_zeta_x8(__m256i w_even,
                                         __m256i w_odd,
                                         __m256i zetas,
                                         __m256i* n_even,
                                         __m256i* n_odd)
{
    __m256i odd;

    intt_butterfly_prepare(w_even, w_odd, n_even, &odd);

    /* Multiply n_odd by zetas (step root) */
    *n_odd = multiply_mod_q(odd, zetas);
}

/*
 * Compact the even (or odd) dwords of 2 vectors into a single one, according
 * to the given vpermd index vector.
 */
IPPCP_INLINE __m256i compact_dwords(__m256i a, __m256i b, __m256i idx)
{
    __m256i lo = _mm256_permutevar8x32_epi32(a, idx); /* [0,2,4,6 | 0,2,4,6] */
    __m256i hi = _mm256_permutevar8x32_epi32(b, idx); /* [8,10,12,14 | ...] */

    return _mm256_blend_epi32(lo, hi, 0xf0);          /* [0,2,4,6 | 8,10,12,14] */
}

/*-
 ******************************************************************************
 * intt_levels0to4
 *
 * Description:
 *   Executes the first five stages (levels 0-4) of the INTT on groups of 64
 *   coefficients (8 vectors).
 *
 *   This function hierarchically mixes and transforms groups of coefficients
 *   using butterfly operations and level specific zeta (twiddle) factors,
 *   performing all required re-packing and permutations for each layer.
 *
 *   Each call operates on a block of 64 coefficients, and must be repeated 4
 *   times (with offsets 0, 64, 128, 192) to process all 256 coefficients.
 *
 * Layer/Level details:
 *   - Level 0: offset = 1,   step = 128;  zeta indexes (new) = 0..127
 *   - Level 1: offset = 2,   step = 64;   zeta indexes (new) = 128..191
 *   - Level 2: offset = 4,   step = 32;   zeta indexes (new) = 192..223
 *   - Level 3: offset = 8,   step = 16;   zeta indexes (new) = 224..239
 *   - Level 4: offset = 16,  step = 8;    zeta indexes (new) = 240..247
 *
 * Arguments:
 *   c                  - pointer to the first of a set of 64 coefficients
 *   z0, z1, z2, z3, z4 - pointers into the zeta table for each INTT
 *                        level 0..4
 *
 * Output:
 *   Updated coefficients are written in-place in memory.
 *
 * Notes:
 *   - Function must be called 4 times for a full 256-coefficient INTT layer
 *     sweep.
 ******************************************************************************
 */
IPPCP_INLINE void intt_levels0to4(Ipp32s* c,
                                  const Ipp32s* z0,
                                  const Ipp32s* z1,
                                  const Ipp32s* z2,
                                  const Ipp32s* z3,
                                  const Ipp32s* z4)
{
    const __m256i idx_even = _mm256_setr_epi32(0, 2, 4, 6, 0, 2, 4, 6);
    const __m256i idx_odd  = _mm256_setr_epi32(1, 3, 5, 7, 1, 3, 5, 7);
    __m256i w0, w1, w2, w3, w4, w5, w6, w7, a, b, t0, t1, z;

    /*-
     * ==============================================================
     * level 0: offset = 1, step = 128
     * zeta indexes (original table) = 255, 254, 253, ... 129, 128
     * zeta indexes (new table) = 0, 1, 2, .. 127
     *
     * dword layout in memory:
     *   a = [0,1,2,3 | 4,5,6,7]
     *   b = [8,9,10,11 | 12,13,14,15]
     * required dword layout in registers:
     *   w0 = [0,2,4,6 | 8,10,12,14]
     *   w1 = [1,3,5,7 | 9,11,13,15]
     */

    /* load w_even and w_odd */
    a = load_x8(c + 0);
    b = load_x8(c + 8);

    /* compact even words into w0 (w_even[0:7]) */
    w0 = compact_dwords(a, b, idx_even);

    /* compact odd words into w1 (w_odd[0:7]) */
    w1 = compact_dwords(a, b, idx_odd);

    /* load 8 zetas */
    z = load_x8(&z0[0]);
    intt_butterfly_zeta_x8(w0, w1, z, &w0, &w1);

    /* load w_even and w_odd */
    a = load_x8(c + 16);
    b = load_x8(c + 24);

    /* compact even words into w2 (w_even[8:15]) */
    w2 = compact_dwords(a, b, idx_even);

    /* compact odd words into w3 (w_odd[8:15]) */
    w3 = compact_dwords(a, b, idx_odd);

    /* load 8 zetas */
    z = load_x8(&z0[8]);
    intt_butterfly_zeta_x8(w2, w3, z, &w2, &w3);

    /* load w_even and w_odd */
    a = load_x8(c + 32);
    b = load_x8(c + 40);

    /* compact even words into w4 (w_even[16:23]) */
    w4 = compact_dwords(a, b, idx_even);

    /* compact odd words into w5 (w_odd[16:23]) */
    w5 = compact_dwords(a, b, idx_odd);

    /* load 8 zetas */
    z = load_x8(&z0[16]);
    intt_butterfly_zeta_x8(w4, w5, z, &w4, &w5);

    /* load w_even and w_odd */
    a = load_x8(c + 48);
    b = load_x8(c + 56);

    /* compact even words into w6 (w_even[24:31]) */
    w6 = compact_dwords(a, b, idx_even);

    /* compact odd words into w7 (w_odd[24:31]) */
    w7 = compact_dwords(a, b, idx_odd);

    /* load 8 zetas */
    z = load_x8(&z0[24]);
    intt_butterfly_zeta_x8(w6, w7, z, &w6, &w7);

    /*-
     * ==============================================================
     * level 1: offset = 2, step = 64
     * zeta indexes = 127, 126, 125, ... 65, 64
     * zeta indexes (new) = 128, 129, .. 191
     *
     * Result DWORD layout:
     *   w0 = [0,  2,  4,  6,  8, 10, 12, 14]
     *   w1 = [1,  3,  5,  7,  9, 11, 13, 15]
     * Desired layout for this phase:
     *   w0 = [0,1,4,5,8,9,12,13]
     *   w1 = [2,3,6,7,10,11,14,15]
     */

    /* Interleave even/odd within each 128-bit lane: */
    t0 = _mm256_unpacklo_epi32(w0, w1); /* A = [0,1,2,3 | 8,9,10,11] */
    t1 = _mm256_unpackhi_epi32(w0, w1); /* B = [4,5,6,7 | 12,13,14,15] */

    w0 = shufps_x8(t0, t1, 0x44);       /* [0,1,4,5 | 8,9,12,13] */
    w1 = shufps_x8(t0, t1, 0xee);       /* [2,3,6,7 | 10,11,14,15] */

    /* load 4 zetas and populate across the vector: [0 - 1 -] [2 - 3 -] */
    z = load_zeta_x4(&z1[0]);
    intt_butterfly(w0, w1, z, &w0, &w1);

    /* Interleave even/odd within each 128-bit lane: */
    t0 = _mm256_unpacklo_epi32(w2, w3); /* A = [0,1,2,3 | 8,9,10,11] */
    t1 = _mm256_unpackhi_epi32(w2, w3); /* B = [4,5,6,7 | 12,13,14,15] */

    w2 = shufps_x8(t0, t1, 0x44);       /* [0,1,4,5 | 8,9,12,13] */
    w3 = shufps_x8(t0, t1, 0xee);       /* [2,3,6,7 | 10,11,14,15] */

    /* load 4 zetas and populate across the vector */
    z = load_zeta_x4(&z1[4]);
    intt_butterfly(w2, w3, z, &w2, &w3);

    /* Interleave even/odd within each 128-bit lane: */
    t0 = _mm256_unpacklo_epi32(w4, w5); /* A = [0,1,2,3 | 8,9,10,11] */
    t1 = _mm256_unpackhi_epi32(w4, w5); /* B = [4,5,6,7 | 12,13,14,15] */

    w4 = shufps_x8(t0, t1, 0x44);       /* [0,1,4,5 | 8,9,12,13] */
    w5 = shufps_x8(t0, t1, 0xee);       /* [2,3,6,7 | 10,11,14,15] */

    /* load 4 zetas and populate across the vector */
    z = load_zeta_x4(&z1[8]);
    intt_butterfly(w4, w5, z, &w4, &w5);

    /* Interleave even/odd within each 128-bit lane: */
    t0 = _mm256_unpacklo_epi32(w6, w7); /* A = [0,1,2,3 | 8,9,10,11] */
    t1 = _mm256_unpackhi_epi32(w6, w7); /* B = [4,5,6,7 | 12,13,14,15] */

    w6 = shufps_x8(t0, t1, 0x44);       /* [0,1,4,5 | 8,9,12,13] */
    w7 = shufps_x8(t0, t1, 0xee);       /* [2,3,6,7 | 10,11,14,15] */

    /* load 4 zetas and populate across the vector */
    z = load_zeta_x4(&z1[12]);
    intt_butterfly(w6, w7, z, &w6, &w7);

    /*-
     * ==============================================================
     * level 2: offset = 4, step = 32
     * zeta indexes = 63, 62, 61, ... 33, 32
     * zeta indexes (new) = 192, 193, 194, ... 223
     *
     * Result DWORD layout:
     *   w0 = [0,1,4,5,8,9,12,13]
     *   w1 = [16,17,20,21,24,25,28,29]
     * Desired layout:
     *   t0 = [0,1,2,3, 8,9,10,11]
     *   w1 = [4,5,6,7, 12,13,14,15]
     */
    t0 = shufps_x8(w0, w1, 0x44); /* t0 = [0,1,2,3 | 8,9,10,11] */
    w1 = shufps_x8(w0, w1, 0xee); /* w1 = [4,5,6,7 | 12,13,14,15] */

    /* broadcast zetas */
    z = bcast_zeta_x2(&z2[0]);
    intt_butterfly(t0, w1, z, &w0, &w1);

    t0 = shufps_x8(w2, w3, 0x44);
    w3 = shufps_x8(w2, w3, 0xee);

    /* broadcast zetas */
    z = bcast_zeta_x2(&z2[2]);
    intt_butterfly(t0, w3, z, &w2, &w3);

    t0 = shufps_x8(w4, w5, 0x44);
    w5 = shufps_x8(w4, w5, 0xee);

    /* broadcast zetas */
    z = bcast_zeta_x2(&z2[4]);
    intt_butterfly(t0, w5, z, &w4, &w5);

    t0 = shufps_x8(w6, w7, 0x44);
    w7 = shufps_x8(w6, w7, 0xee);

    /* broadcast zetas */
    z = bcast_zeta_x2(&z2[6]);
    intt_butterfly(t0, w7, z, &w6, &w7);

    /*-
     * ==============================================================
     * level 3: offset = 8, step = 16
     * zeta indexes = 31, 30, 29, ... 17, 16
     * zeta indexes (new) = 224, 225, 226, ... 239
     *
     *   w0 = [0,1,2,3 | 8,9,10,11]
     *   w1 = [16,17,18,19 | 24,25,26,27]
     */
    t0 = _mm256_permute2x128_si256(w0, w1, 0x20); /* [0,1,2,3 | 4,5,6,7] */
    w1 = _mm256_permute2x128_si256(w0, w1, 0x31); /* [8,..,11 | 12,..,15] */

    /* broadcast zetas */
    z = bcast_zeta(&z3[0]);
    intt_butterfly(t0, w1, z, &w0, &w1);

    t0 = _mm256_permute2x128_si256(w2, w3, 0x20);
    w3 = _mm256_permute2x128_si256(w2, w3, 0x31);

    /* broadcast zetas */
    z = bcast_zeta(&z3[1]);
    intt_butterfly(t0, w3, z, &w2, &w3);

    t0 = _mm256_permute2x128_si256(w4, w5, 0x20); /* [0,1,2,3 | 4,5,6,7] */
    w5 = _mm256_permute2x128_si256(w4, w5, 0x31); /* [8,..,11 | 12,..,15] */

    /* broadcast zetas */
    z = bcast_zeta(&z3[2]);
    intt_butterfly(t0, w5, z, &w4, &w5);

    t0 = _mm256_permute2x128_si256(w6, w7, 0x20);
    w7 = _mm256_permute2x128_si256(w6, w7, 0x31);

    /* broadcast zetas */
    z = bcast_zeta(&z3[3]);
    intt_butterfly(t0, w7, z, &w6, &w7);

    /*
     * ==============================================================
     * level 4: offset = 16, step = 8
     * zeta indexes = 15, 14, 13, ..., 9, 8
     * zeta indexes (new) = 240, 241, 242, ... 247
     */

    /* broadcast zetas */
    z = bcast_zeta(&z4[0]);
    intt_butterfly(w0, w2, z, &w0, &w2);
    intt_butterfly(w1, w3, z, &w1, &w3);

    /* broadcast zetas */
    z = bcast_zeta(&z4[1]);
    intt_butterfly(w4, w6, z, &w4, &w6);
    intt_butterfly(w5, w7, z, &w5, &w7);

    /* Store new w_even and w_odd */
    store_x8(c + 0, w0);
    store_x8(c + 8, w1);
    store_x8(c + 16, w2);
    store_x8(c + 24, w3);
    store_x8(c + 32, w4);
    store_x8(c + 40, w5);
    store_x8(c + 48, w6);
    store_x8(c + 56, w7);
}

/*-
 ******************************************************************************
 * intt_levels5to7
 *
 * Description:
 *   Processes the last three levels (5 to 7) of the INTT on 64 coefficients.
 *
 *   It completes the hierarchical merging of INTT, applying stage-specific
 *   zeta (twiddle) factors and modular butterfly operations for each level,
 *   and performs the final post-processing Montgomery multiplication at the
 *   end of the transform.
 *
 *   It must be invoked 4 times with offsets equal to 0, 8, 16 and 24 to cover
 *   all 256 coefficients.
 *
 * Layer/Level details:
 *   - Level 5: offset =  32, step = 4;   zeta indexes (new) = 248..251
 *   - Level 6: offset =  64, step = 2;   zeta indexes (new) = 252, 253
 *   - Level 7: offset = 128, step = 1;   zeta index   (new) = 254
 *
 *   After all INTT levels, multiplies the output by the Montgomery factor
 *   corresponding to the inverse transform scaling (usually the modular
 *   inverse of the NTT degree in Montgomery form), to obtain the final
 *   reduced coefficients.
 *
 * Arguments:
 *   c       - pointer to the first of a group of 8 coefficients
 *   zetas   - pointer to the zetas (twiddle factors) table
 *
 * Output:
 *   Overwrites memory at the given offset with the INTT-processed
 *   coefficients.
 *
 * Notes:
 *   - This function must be called 4 times with appropriate offsets to
 *     process all 256 coefficients.
 ******************************************************************************
 */
IPPCP_INLINE void intt_levels5to7(Ipp32s* c, const Ipp32s* zetas)
{
    __m256i w0, w1, w2, w3, w4, w5, w6, w7, z;

    w0 = load_x8(c + 0);
    w1 = load_x8(c + 32);
    w2 = load_x8(c + 64);
    w3 = load_x8(c + 96);
    w4 = load_x8(c + 128);
    w5 = load_x8(c + 160);
    w6 = load_x8(c + 192);
    w7 = load_x8(c + 224);

    /*
     * ==============================================================
     * level 5: offset = 32, step = 4
     */
    z = bcast_zeta(&zetas[248]);
    intt_butterfly(w0, w1, z, &w0, &w1);

    z = bcast_zeta(&zetas[249]);
    intt_butterfly(w2, w3, z, &w2, &w3);

    z = bcast_zeta(&zetas[250]);
    intt_butterfly(w4, w5, z, &w4, &w5);

    z = bcast_zeta(&zetas[251]);
    intt_butterfly(w6, w7, z, &w6, &w7);

    /*
     * ==============================================================
     * level 6: offset = 64, step = 2
     */
    z = bcast_zeta(&zetas[252]);
    intt_butterfly(w0, w2, z, &w0, &w2);
    intt_butterfly(w1, w3, z, &w1, &w3);

    z = bcast_zeta(&zetas[253]);
    intt_butterfly(w4, w6, z, &w4, &w6);
    intt_butterfly(w5, w7, z, &w5, &w7);

    /*
     * ==============================================================
     * level 7: offset = 128, step = 1
     */
    z = bcast_zeta(&zetas[254]);
    intt_butterfly(w0, w4, z, &w0, &w4);
    intt_butterfly(w1, w5, z, &w1, &w5);
    intt_butterfly(w2, w6, z, &w2, &w6);
    intt_butterfly(w3, w7, z, &w3, &w7);

    /*
     * ==============================================================
     * extra multiply
     */
    z = _mm256_set1_epi32(ML_DSA_DEGREE_INV_MONTGOMERY);

    w0 = multiply_mod_q_bcast32(w0, z);
    w4 = multiply_mod_q_bcast32(w4, z);
    w1 = multiply_mod_q_bcast32(w1, z);
    w5 = multiply_mod_q_bcast32(w5, z);
    w2 = multiply_mod_q_bcast32(w2, z);
    w6 = multiply_mod_q_bcast32(w6, z);
    w3 = multiply_mod_q_bcast32(w3, z);
    w7 = multiply_mod_q_bcast32(w7, z);

    store_x8(c + 0, w0);
    store_x8(c + 32, w1);
    store_x8(c + 64, w2);
    store_x8(c + 96, w3);
    store_x8(c + 128, w4);
    store_x8(c + 160, w5);
    store_x8(c + 192, w6);
    store_x8(c + 224, w7);
}

/*-
 ******************************************************************************
 * zetas_inverse:
 *
 * Description:

 *   Table of inverse NTT "zetas" (twiddle factors), precomputed as powers of
 *   the primitive root of unity (mod Q) required for each stage of the inverse
 *   Number Theoretic Transform (INTT). Entries represent the modular inverses
 *   of the forward NTT zetas, arranged in bit-reversed or stage-order as
 *   required by the INTT implementation.  Elements of the table are in
 *   reversed order vs the original table for the forward NTT. This is to
 *   reduce permute operations when preparing zetas in the correct format for
 *   butterfly operations.
 *
 *   Each entry corresponds to a 32-bit modular value (Q - zeta) for the
 *   appropriate stage and index.
 *
 *   The exact arrangement and computation of these zetas matches the INTT
 *   schedule and must be consistent with the NTT forward transform.
 ******************************************************************************
 */
static const __ALIGN64 Ipp32s zetas_inverse[CP_ML_N] = {
    CP_ML_DSA_Q - 1976782, CP_ML_DSA_Q - 7534263, CP_ML_DSA_Q - 1400424, CP_ML_DSA_Q - 3937738,
    CP_ML_DSA_Q - 7018208, CP_ML_DSA_Q - 8332111, CP_ML_DSA_Q - 3919660, CP_ML_DSA_Q - 7826001,
    CP_ML_DSA_Q - 4834730, CP_ML_DSA_Q - 1612842, CP_ML_DSA_Q - 7403526, CP_ML_DSA_Q - 183443,
    CP_ML_DSA_Q - 6094090, CP_ML_DSA_Q - 7959518, CP_ML_DSA_Q - 6144432, CP_ML_DSA_Q - 5441381,
    CP_ML_DSA_Q - 4546524, CP_ML_DSA_Q - 8119771, CP_ML_DSA_Q - 7276084, CP_ML_DSA_Q - 6712985,
    CP_ML_DSA_Q - 1910376, CP_ML_DSA_Q - 6577327, CP_ML_DSA_Q - 1723600, CP_ML_DSA_Q - 7953734,
    CP_ML_DSA_Q - 472078,  CP_ML_DSA_Q - 1717735, CP_ML_DSA_Q - 7404533, CP_ML_DSA_Q - 2213111,
    CP_ML_DSA_Q - 269760,  CP_ML_DSA_Q - 3866901, CP_ML_DSA_Q - 3523897, CP_ML_DSA_Q - 5341501,
    CP_ML_DSA_Q - 6581310, CP_ML_DSA_Q - 4686184, CP_ML_DSA_Q - 1652634, CP_ML_DSA_Q - 810149,
    CP_ML_DSA_Q - 3014001, CP_ML_DSA_Q - 1616392, CP_ML_DSA_Q - 162844,  CP_ML_DSA_Q - 5196991,
    CP_ML_DSA_Q - 7173032, CP_ML_DSA_Q - 185531,  CP_ML_DSA_Q - 3369112, CP_ML_DSA_Q - 1957272,
    CP_ML_DSA_Q - 8215696, CP_ML_DSA_Q - 2454455, CP_ML_DSA_Q - 2432395, CP_ML_DSA_Q - 6366809,
    CP_ML_DSA_Q - 4603424, CP_ML_DSA_Q - 594136,  CP_ML_DSA_Q - 4656147, CP_ML_DSA_Q - 5796124,
    CP_ML_DSA_Q - 6533464, CP_ML_DSA_Q - 6709241, CP_ML_DSA_Q - 5548557, CP_ML_DSA_Q - 7838005,
    CP_ML_DSA_Q - 3406031, CP_ML_DSA_Q - 2235880, CP_ML_DSA_Q - 777191,  CP_ML_DSA_Q - 1500165,
    CP_ML_DSA_Q - 7005614, CP_ML_DSA_Q - 5834105, CP_ML_DSA_Q - 1917081, CP_ML_DSA_Q - 7100756,
    CP_ML_DSA_Q - 6417775, CP_ML_DSA_Q - 3306115, CP_ML_DSA_Q - 1312455, CP_ML_DSA_Q - 7929317,
    CP_ML_DSA_Q - 6950192, CP_ML_DSA_Q - 5062207, CP_ML_DSA_Q - 1237275, CP_ML_DSA_Q - 7047359,
    CP_ML_DSA_Q - 7329447, CP_ML_DSA_Q - 1903435, CP_ML_DSA_Q - 1869119, CP_ML_DSA_Q - 5386378,
    CP_ML_DSA_Q - 4832145, CP_ML_DSA_Q - 2635921, CP_ML_DSA_Q - 1250494, CP_ML_DSA_Q - 4613401,
    CP_ML_DSA_Q - 1595974, CP_ML_DSA_Q - 2486353, CP_ML_DSA_Q - 1247620, CP_ML_DSA_Q - 4055324,
    CP_ML_DSA_Q - 1265009, CP_ML_DSA_Q - 5790267, CP_ML_DSA_Q - 2691481, CP_ML_DSA_Q - 2842341,
    CP_ML_DSA_Q - 203044,  CP_ML_DSA_Q - 1735879, CP_ML_DSA_Q - 5038140, CP_ML_DSA_Q - 3437287,
    CP_ML_DSA_Q - 4108315, CP_ML_DSA_Q - 5942594, CP_ML_DSA_Q - 286988,  CP_ML_DSA_Q - 342297,
    CP_ML_DSA_Q - 4784579, CP_ML_DSA_Q - 7611795, CP_ML_DSA_Q - 7855319, CP_ML_DSA_Q - 4823422,
    CP_ML_DSA_Q - 3207046, CP_ML_DSA_Q - 2031748, CP_ML_DSA_Q - 5257975, CP_ML_DSA_Q - 7725090,
    CP_ML_DSA_Q - 7857917, CP_ML_DSA_Q - 8337157, CP_ML_DSA_Q - 6767243, CP_ML_DSA_Q - 495491,
    CP_ML_DSA_Q - 819034,  CP_ML_DSA_Q - 909542,  CP_ML_DSA_Q - 1859098, CP_ML_DSA_Q - 900702,
    CP_ML_DSA_Q - 5187039, CP_ML_DSA_Q - 7183191, CP_ML_DSA_Q - 4621053, CP_ML_DSA_Q - 4860065,
    CP_ML_DSA_Q - 3513181, CP_ML_DSA_Q - 7144689, CP_ML_DSA_Q - 2434439, CP_ML_DSA_Q - 266997,
    CP_ML_DSA_Q - 4817955, CP_ML_DSA_Q - 5933984, CP_ML_DSA_Q - 2244091, CP_ML_DSA_Q - 5037939,
    CP_ML_DSA_Q - 3817976, CP_ML_DSA_Q - 2316500, CP_ML_DSA_Q - 3407706, CP_ML_DSA_Q - 2091667,
    CP_ML_DSA_Q - 3839961, CP_ML_DSA_Q - 4751448, CP_ML_DSA_Q - 4499357, CP_ML_DSA_Q - 5361315,
    CP_ML_DSA_Q - 6940675, CP_ML_DSA_Q - 7567685, CP_ML_DSA_Q - 6795489, CP_ML_DSA_Q - 1285669,
    CP_ML_DSA_Q - 1341330, CP_ML_DSA_Q - 1315589, CP_ML_DSA_Q - 8202977, CP_ML_DSA_Q - 5971092,
    CP_ML_DSA_Q - 6529015, CP_ML_DSA_Q - 3159746, CP_ML_DSA_Q - 4827145, CP_ML_DSA_Q - 189548,
    CP_ML_DSA_Q - 7063561, CP_ML_DSA_Q - 759969,  CP_ML_DSA_Q - 8169440, CP_ML_DSA_Q - 2389356,
    CP_ML_DSA_Q - 5130689, CP_ML_DSA_Q - 1653064, CP_ML_DSA_Q - 8371839, CP_ML_DSA_Q - 4656075,
    CP_ML_DSA_Q - 3958618, CP_ML_DSA_Q - 904516,  CP_ML_DSA_Q - 7280319, CP_ML_DSA_Q - 44288,
    CP_ML_DSA_Q - 3097992, CP_ML_DSA_Q - 508951,  CP_ML_DSA_Q - 264944,  CP_ML_DSA_Q - 5037034,
    CP_ML_DSA_Q - 6949987, CP_ML_DSA_Q - 1852771, CP_ML_DSA_Q - 1349076, CP_ML_DSA_Q - 7998430,
    CP_ML_DSA_Q - 7072248, CP_ML_DSA_Q - 8357436, CP_ML_DSA_Q - 7151892, CP_ML_DSA_Q - 7709315,
    CP_ML_DSA_Q - 5903370, CP_ML_DSA_Q - 7969390, CP_ML_DSA_Q - 4686924, CP_ML_DSA_Q - 5412772,
    CP_ML_DSA_Q - 2715295, CP_ML_DSA_Q - 2147896, CP_ML_DSA_Q - 7396998, CP_ML_DSA_Q - 3412210,
    CP_ML_DSA_Q - 126922,  CP_ML_DSA_Q - 4747489, CP_ML_DSA_Q - 5223087, CP_ML_DSA_Q - 5190273,
    CP_ML_DSA_Q - 7380215, CP_ML_DSA_Q - 4296819, CP_ML_DSA_Q - 1939314, CP_ML_DSA_Q - 7122806,
    CP_ML_DSA_Q - 6795196, CP_ML_DSA_Q - 2176455, CP_ML_DSA_Q - 3475950, CP_ML_DSA_Q - 6927966,
    CP_ML_DSA_Q - 5339162, CP_ML_DSA_Q - 4702672, CP_ML_DSA_Q - 6851714, CP_ML_DSA_Q - 4450022,
    CP_ML_DSA_Q - 5582638, CP_ML_DSA_Q - 2071892, CP_ML_DSA_Q - 5823537, CP_ML_DSA_Q - 3900724,
    CP_ML_DSA_Q - 3881043, CP_ML_DSA_Q - 954230,  CP_ML_DSA_Q - 531354,  CP_ML_DSA_Q - 811944,
    CP_ML_DSA_Q - 3699596, CP_ML_DSA_Q - 6779997, CP_ML_DSA_Q - 6239768, CP_ML_DSA_Q - 3507263,
    CP_ML_DSA_Q - 4558682, CP_ML_DSA_Q - 3505694, CP_ML_DSA_Q - 6736599, CP_ML_DSA_Q - 6681150,
    CP_ML_DSA_Q - 7841118, CP_ML_DSA_Q - 2348700, CP_ML_DSA_Q - 8079950, CP_ML_DSA_Q - 3539968,
    CP_ML_DSA_Q - 5512770, CP_ML_DSA_Q - 3574422, CP_ML_DSA_Q - 5336701, CP_ML_DSA_Q - 4519302,
    CP_ML_DSA_Q - 3915439, CP_ML_DSA_Q - 5842901, CP_ML_DSA_Q - 4788269, CP_ML_DSA_Q - 6718724,
    CP_ML_DSA_Q - 3530437, CP_ML_DSA_Q - 3077325, CP_ML_DSA_Q - 95776,   CP_ML_DSA_Q - 2706023,
    CP_ML_DSA_Q - 280005,  CP_ML_DSA_Q - 4010497, CP_ML_DSA_Q - 8360995, CP_ML_DSA_Q - 1757237,
    CP_ML_DSA_Q - 5102745, CP_ML_DSA_Q - 6980856, CP_ML_DSA_Q - 4520680, CP_ML_DSA_Q - 6262231,
    CP_ML_DSA_Q - 6271868, CP_ML_DSA_Q - 2619752, CP_ML_DSA_Q - 7260833, CP_ML_DSA_Q - 7830929,
    CP_ML_DSA_Q - 3585928, CP_ML_DSA_Q - 7300517, CP_ML_DSA_Q - 1024112, CP_ML_DSA_Q - 2725464,
    CP_ML_DSA_Q - 2680103, CP_ML_DSA_Q - 3111497, CP_ML_DSA_Q - 5495562, CP_ML_DSA_Q - 3119733,
    CP_ML_DSA_Q - 6288512, CP_ML_DSA_Q - 8021166, CP_ML_DSA_Q - 2353451, CP_ML_DSA_Q - 1826347,
    CP_ML_DSA_Q - 466468,  CP_ML_DSA_Q - 7504169, CP_ML_DSA_Q - 7602457, CP_ML_DSA_Q - 237124,
    CP_ML_DSA_Q - 7861508, CP_ML_DSA_Q - 5771523, CP_ML_DSA_Q - 25847,   CP_ML_DSA_Q - 4193792,
};

/*-
 ******************************************************************************
 * zetas_montgomery:
 *
 * Description:
 *   Table of reduced Montgomery zeta reduce(zeta * (2^32 * 2^32 mod(q)).
 ******************************************************************************
 */
static const Ipp32s zetas_montgomery[256] = {
    4193792, 25847,   5771523, 7861508, 237124,  7602457, 7504169, 466468,  1826347, 2353451,
    8021166, 6288512, 3119733, 5495562, 3111497, 2680103, 2725464, 1024112, 7300517, 3585928,
    7830929, 7260833, 2619752, 6271868, 6262231, 4520680, 6980856, 5102745, 1757237, 8360995,
    4010497, 280005,  2706023, 95776,   3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150, 6736599,
    3505694, 4558682, 3507263, 6239768, 6779997, 3699596, 811944,  531354,  954230,  3881043,
    3900724, 5823537, 2071892, 5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950,
    2176455, 6795196, 7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370, 7709315, 7151892,
    8357436, 7072248, 7998430, 1349076, 1852771, 6949987, 5037034, 264944,  508951,  3097992,
    44288,   7280319, 904516,  3958618, 4656075, 8371839, 1653064, 5130689, 2389356, 8169440,
    759969,  7063561, 189548,  4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961, 2091667, 3407706,
    2316500, 3817976, 5037939, 2244091, 5933984, 4817955, 266997,  2434439, 7144689, 3513181,
    4860065, 4621053, 7183191, 5187039, 900702,  1859098, 909542,  819034,  495491,  6767243,
    8337157, 7857917, 7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
    342297,  286988,  5942594, 4108315, 3437287, 5038140, 1735879, 203044,  2842341, 2691481,
    5790267, 1265009, 4055324, 1247620, 2486353, 1595974, 4613401, 1250494, 2635921, 4832145,
    5386378, 1869119, 1903435, 7329447, 7047359, 1237275, 5062207, 6950192, 7929317, 1312455,
    3306115, 6417775, 7100756, 1917081, 5834105, 7005614, 1500165, 777191,  2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136,  4603424, 6366809, 2432395,
    2454455, 8215696, 1957272, 3369112, 185531,  7173032, 5196991, 162844,  1616392, 3014001,
    810149,  1652634, 4686184, 6581310, 5341501, 3523897, 3866901, 269760,  2213111, 7404533,
    1717735, 472078,  7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443,  7403526, 1612842, 4834730, 7826001, 3919660,
    8332111, 7018208, 3937738, 1400424, 7534263, 1976782
};



/*-
 ******************************************************************************
 * cp_ml_multiplyNTT
 *
 * Description:
 *   Top-level routine for polynomial multiplication in ML-DSA,
 *   using number-theoretic transform (NTT) methods. This function performs
 *   multiplication of two polynomials in the NTT domain, making full use of
 *   AVX2 vector instructions.
 *   It assumes there are 256 coefficients.
 *
 *   out[i] = a[i] x b[i] mod Q
 *
 *   The function:
 *     - Takes pointers to source polynomials (NTT domain) and destination buffer
 *     - Performs element-wise modular (pointwise) multiplication in the NTT domain
 *     - Applies Montgomery reduction for efficient modular arithmetic
 *
 * Inputs:
 *   a   - First input polynomial, NTT domain
 *   b   - Second input polynomial, NTT domain
 *   out - Destination buffer for output coefficients
 *
 * Output:
 *   - Output buffer 'out' contains the coefficient-wise modular product of
 *     the input polynomials (still in NTT domain)
 ******************************************************************************
 */
IPP_OWN_DEFN(void, cp_ml_multiplyNTT, (const IppPoly* in1, const IppPoly* in2, IppPoly* out))
{
    const Ipp32s* a = &in1->values[0];
    const Ipp32s* b = &in2->values[0];
    Ipp32s* c       = &out->values[0];
    int i;

    for (i = 0; i < CP_ML_N; i += 8) {
        /* Load a and b, multiply this part of the input data */
        __m256i r = multiply_mod_q_signed(load_x8(a + i), load_x8(b + i));

        /* store result to output */
        store_x8(c + i, r);
    }
    return;
}

/*-
 ******************************************************************************
 * cp_ml_NTT()
 *
 * Description:
 *   Top-level implementation of the forward Number Theoretic
 *   Transform (NTT) of ML-DSA polynomials. This function converts a
 *   polynomial from its standard coefficient (normal) form to its NTT
 *   representation, storing the result in-place in the provided
 *   coefficients array. The function uses stage-specific "zeta"
 *   (twiddle factor) tables.
 *
 *   The function:
 *     - Takes a buffer of polynomial coefficients in normal (standard) order
 *     - Processes the NTT in a breadth-first, layered fashion with AVX2 SIMD
 *     - Overwrites the input buffer with its NTT-domain representation
 *
 * Inputs:
 *   p_coeffs - Pointer to the coefficient array (will be overwritten in-place
 *              by the NTT result)
 *
 * Output:
 *   - The 'values' array in f is updated in-place with the corresponding
 *     NTT-domain representation.
 ******************************************************************************
 */
IPP_OWN_DEFN(void, cp_ml_NTT, (IppPoly * f))
{
    const Ipp32s* p_zetas = &zetas_montgomery[0];
    Ipp32s* p_coeffs      = &f->values[0];

    /*
     * The levels below need every coefficient in [0, Q), while callers pass
     * signed, unreduced coefficients (s1, s2, t0, y, c, z). Lift them first -
     * see canonicalize_x8().
     */
    for (int i = 0; i < CP_ML_N; i += 8) {
        store_x8(p_coeffs + i, canonicalize_x8(load_x8(p_coeffs + i)));
    }

    /*
     * ==============================================================
     * - level 0: offset = 128, step = 1, zeta indexes = 1
     * - level 1: offset = 64, step = 2, zeta indexes = 2, 3
     * - level 2: offset = 32, step = 4, zeta indexes = 4, 5, 6, 7
     */
    ntt_levels0to2(p_coeffs + 0, p_zetas);
    ntt_levels0to2(p_coeffs + 8, p_zetas);
    ntt_levels0to2(p_coeffs + 16, p_zetas);
    ntt_levels0to2(p_coeffs + 24, p_zetas);

    /*
     * ==============================================================
     * - level 3: offset = 16, step = 8
     *     zeta indexes = 8, 9, 10, 11, 12, 13, 14, 15
     * - level 4: offset = 8, step = 16
     *     zeta indexes = 16, 17, 18, ..., 30, 31
     * - level 5: offset = 4, step = 32
     *     zeta indexes = 32, 33, 34, ..., 62, 63
     * - level 6: offset = 2, step = 64
     *     zeta indexes = 64, 65, 66, ..., 126, 127
     * - level 7: offset = 1, step = 128
     *     zeta indexes = 128, 129, 130, ..., 254, 255
     */

    /* arguments:  coeff,             l3,           l4, l5, l6, l7 */
    ntt_levels3to7(p_coeffs + 0,
                   p_zetas + 8,
                   p_zetas + 16,
                   p_zetas + 32,
                   p_zetas + 64,
                   p_zetas + 128);
    ntt_levels3to7(p_coeffs + 64,
                   p_zetas + 10,
                   p_zetas + 20,
                   p_zetas + 40,
                   p_zetas + 80,
                   p_zetas + 160);
    ntt_levels3to7(p_coeffs + 128,
                   p_zetas + 12,
                   p_zetas + 24,
                   p_zetas + 48,
                   p_zetas + 96,
                   p_zetas + 192);
    ntt_levels3to7(p_coeffs + 192,
                   p_zetas + 14,
                   p_zetas + 28,
                   p_zetas + 56,
                   p_zetas + 112,
                   p_zetas + 224);

    return;
}

/*-
 ******************************************************************************
 * cp_ml_inverseNTT
 *
 * Description:
 *   Top-level implementation of the inverse Number Theoretic
 *   Transform (INTT) of ML-DSA polynomial. This function converts a
 *   polynomial from its NTT domain back to the standard coefficient
 *   (normal) domain, storing the result in-place in the provided
 *   buffer. The required inverse zeta (twiddle) factors are managed
 *   internally.
 *
 *   The function:
 *     - Accepts a buffer of NTT-domain coefficients
 *     - Overwrites the input buffer with the result in the normal
 *       (coefficient) domain
 *
 * Inputs:
 *   IppPoly - Points to the polynomial coefficient array (in-place transform)
 *
 * Output:
 *   - The 'values' array in poly f is updated in-place to contain the
 *      standard domain polynomial.
 *   - Uses 'zetas_inverse' table
 ******************************************************************************
 */
IPP_OWN_DEFN(void, cp_ml_inverseNTT, (IppPoly * f, int addq))
{
    const Ipp32s* z  = zetas_inverse;
    Ipp32s* p_coeffs = &f->values[0];

    /*
     * The levels below need every coefficient in [0, Q), while the callers hand
     * over centered representatives: every producer of an INTT input ends in
     * cp_ml_montgomeryReduce() (cp_ml_multiplyNTT) or in
     * cp_ml_simplifiedBarrettReduce() (cp_ml_addNTT / cp_ml_subNTT), each of
     * which may return a negative value. Lift them first - see
     * canonicalize_x8().
     */
    for (int i = 0; i < CP_ML_N; i += 8) {
        store_x8(p_coeffs + i, canonicalize_x8(load_x8(p_coeffs + i)));
    }

    /*
     * ==============================================================
     * - level 0: offset = 1, step = 128
     *     zeta indexes (original table) = 255, 254, 253, ... 129, 128
     *     zeta indexes (new table) = 0, 1, 2, .. 127
     * - level 1: offset = 2, step = 64
     *     zeta indexes (original table) = 127, 126, 125, ... 65, 64
     *     zeta indexes (new table) = 128, 129, .. 191
     * - level 2: offset = 4, step = 32
     *     zeta indexes (original table) = 63, 62, 61, ... 33, 32
     *     zeta indexes (new table) = 192, 193, 194, ... 223
     * - level 3: offset = 8, step = 16
     *     zeta indexes (original table) = 31, 30, 29, ... 17, 16
     *     zeta indexes (new table) = 224, 225, 226, ... 239
     * - level 4: offset = 16, step = 8
     *     zeta indexes (original table) = 15, 14, 13, ..., 9, 8
     *     zeta indexes (new table) = 240, 241, 242, ... 247
     */

    /* arguments:   coeff,          l0,      l1,      l2,      l3,      l4 */
    intt_levels0to4(p_coeffs + 0, z + 0, z + 128, z + 192, z + 224, z + 240);
    intt_levels0to4(p_coeffs + 64, z + 32, z + 144, z + 200, z + 228, z + 242);
    intt_levels0to4(p_coeffs + 128, z + 64, z + 160, z + 208, z + 232, z + 244);
    intt_levels0to4(p_coeffs + 192, z + 96, z + 176, z + 216, z + 236, z + 246);

    /*
     * ==============================================================
     * - level 5: offset = 32, step = 4
     *   zeta indexes (original table) = 7, 6, 5, 4
     *   zeta indexes (new table) = 248, 249, 250, 251
     * - level 6: offset = 64, step = 2
     *   zeta indexes (original table) = 3, 2
     *   zeta indexes (new table) = 252, 253
     * - level 7: offset = 128, step = 1
     *   zeta indexes (original table) = 1
     *   zeta indexes (new table) = 254
     */
    intt_levels5to7(p_coeffs + 0, z);
    intt_levels5to7(p_coeffs + 8, z);
    intt_levels5to7(p_coeffs + 16, z);
    intt_levels5to7(p_coeffs + 24, z);

    /*
     * extra reduce step for montgomery to add q
     *
     * Still required: the levels above leave the coefficients in [0, Q), but
     * cp_ml_polyInfinityNormCheck() (checks 1 and 3 of Algorithm 7) needs the
     * centered representative. center_x8() is the vector form of the scalar
     * tail and gives bit-identical results, since the input is non-negative.
     */
    if (addq == 1) {
        for (int i = 0; i < CP_ML_N; i += 8) {
            store_x8(p_coeffs + i, center_x8(load_x8(p_coeffs + i)));
        }
    }

    return;
}

#endif // #if (_IPP32E >= _IPP32E_L9)
