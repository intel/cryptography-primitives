/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/sm2/ifma_arith_nsm2.h"
#include "gfpec/sm2/ifma_arith_psm2.h"
#include "gfpec/sm2/ifma_defs_sm2.h"

/*
 * EC SM2 base point order
 * in 2^52 radix
 */
static const __ALIGN64 Ipp64u nsm2_x1[PSM2_LEN52] = {
    0x000bf40939d54123, 0x0006b21c6052b53b, 0x000fffffff7203df, 0x000fffffffffffff, 0x0000fffffffeffff};

/* k0 = -( (1/nsm2) mod 2^DIGIT_SIZE_52 ) mod 2^DIGIT_SIZE_52 */
static const Ipp64u nsm2_k0 = 0x000f9e8872350975;

/* r = 2^((52*8)) mod nsm2 */
static const __ALIGN64 Ipp64u nsm2_r[PSM2_LEN52] = {
    0x00062abedd000000, 0x00006cb726ecad3c, 0x00056c361b698a7e, 0x0000000008dfc209, 0x0000010000000000};

/* To Montgomery conversion constant
 * rr = 2^((52*6)*2) mod nsm2
 */
static const __ALIGN64 Ipp64u nsm2_rr[PSM2_LEN52] = {
    0x000643f5455b3830, 0x000c453935b521eb, 0x0009ec21d42b082e, 0x0004d74634238016, 0x0000ca6ea35cbdde};

static const __ALIGN64 Ipp64u ones[PSM2_LEN52] = {
    0x1, 0x0, 0x0, 0x0};

#define MULT_ROUND(R, A, B, IDX)                                               \
    const fesm2 Bi##R##IDX     = permutexvar_i8(idx##IDX, (B));                \
    const fesm2 amBiLo##R##IDX = madd52lo_i64(zero, (A), Bi##R##IDX);          \
    fesm2 tr##R##IDX           = madd52hi_i64(zero, (A), Bi##R##IDX);          \
    {                                                                          \
        /* low */                                                              \
        (R)            = add_i64((R), amBiLo##R##IDX);                         \
        const fesm2 R0 = permutexvar_i8(idx0, (R));                            \
        const fesm2 u  = madd52lo_i64(zero, R0, K0); /* u = R0 * K0 */         \
        tr##R##IDX     = madd52hi_i64(tr##R##IDX, N, u);                       \
        (R)            = madd52lo_i64((R), N, u);                              \
        /* shift */                                                            \
        const fesm2 carryone = maskz_srai_i64(maskone, (R), DIGIT_SIZE_52);    \
        tr##R##IDX           = add_i64(tr##R##IDX, carryone);                  \
        (R)                  = maskz_permutexvar_i8(mask_sr64, idx_sr64, (R)); \
        /* hi */                                                               \
        (R) = add_i64((R), tr##R##IDX);                                        \
    }

/* R = (A*B) - no normalization (in radix 2^52) */
IPP_OWN_DEFN(fesm2, fesm2_mul_norder, (const fesm2 a, const fesm2 b)) {
    const fesm2 N       = FESM2_LOADU(nsm2_x1); /* p */
    const fesm2 K0      = set1_i64(nsm2_k0);
    const fesm2 zero    = setzero_i64();
    const mask8 maskone = 0x1;
    /* index broadcast */
    const fesm2 idx0 = set_i64(REPL8(0x0706050403020100)); //  7,  6,  5,  4,  3,  2,  1,  0
    const fesm2 idx1 = set_i64(REPL8(0x0f0e0d0c0b0a0908)); // 15, 14, 13, 12, 11, 10,  9,  8
    const fesm2 idx2 = set_i64(REPL8(0x1716151413121110)); // 23, 22, 21, 20, 19, 18, 17, 16
    const fesm2 idx3 = set_i64(REPL8(0x1f1e1d1c1b1a1918)); // 31, 30, 29, 28, 27, 26, 25, 24
    const fesm2 idx4 = set_i64(REPL8(0x2726252423222120)); // 39, 38, 37, 36, 35, 34, 33, 32
    const fesm2 idx5 = set_i64(REPL8(0x2f2e2d2c2b2a2928)); // 47, 46, 45, 44, 43, 42, 41, 40

    /* shift right 64 bit line [R >> 64] */
    const mask64 mask_sr64 = 0x00FFFFFFFFFFFFFF;
    const fesm2 idx_sr64   = set_i64(0x0,                 //  0,  0,  0,  0,  0,  0,  0,  0
                                     0x3f3e3d3c3b3a3938,  // 63, 62, 61, 60, 59, 58, 57, 56
                                     0x3736353433323130,  // 55, 54, 53, 52, 51, 50, 49, 48
                                     0x2f2e2d2c2b2a2928,  // 47, 46, 45, 44, 43, 42, 41, 40
                                     0x2726252423222120,  // 39, 38, 37, 36, 35, 34, 33, 32
                                     0x1f1e1d1c1b1a1918,  // 31, 30, 29, 28, 27, 26, 25, 24
                                     0x1716151413121110,  // 23, 22, 21, 20, 19, 18, 17, 16
                                     0x0f0e0d0c0b0a0908); // 15, 14, 13, 12, 11, 10, 9, 8

    fesm2 r = setzero_i64();
    /* PSM2
     * m' mod b = 1
     *
     * Algorithm
     * a[] b[] - input data ((in radix 2^52)) m[] - module nsm2
     *
     * when u =  R[0]*m' mod b
     * 1) R = R + a[] * b[i] (lo)
     * 2) R = R + m[] * u    (lo)
     * 3) R = R >> 64
     * 4) R = R + a[] * b[i] (hi)
     * 5) R = R + m[] * u    (hi)
     */
    /* one round = O(32) */
    MULT_ROUND(r, a, b, 0)
    MULT_ROUND(r, a, b, 1)
    MULT_ROUND(r, a, b, 2)
    MULT_ROUND(r, a, b, 3)
    MULT_ROUND(r, a, b, 4)
    MULT_ROUND(r, a, b, 5)

    return r;
}

IPP_OWN_DEFN(fesm2, fesm2_add_norder_norm, (const fesm2 a, const fesm2 b)) {
    const fesm2 zero = setzero_i64();
    const fesm2 N    = FESM2_LOADU(nsm2_x1);

    /* r = a + b */
    fesm2 r = add_i64(a, b);
    r       = ifma_lnorm52(r);

    /* t = r - N */
    fesm2 t = sub_i64(r, N);
    t       = ifma_norm52(t);

    /* lt = t < 0 */
    const mask8 lt   = cmp_i64_mask(zero, srli_i64(t, DIGIT_SIZE_52 - 1), _MM_CMPINT_LT);
    const mask8 mask = (mask8)((mask8)0 - ((lt >> 4) & 1));

    /* mask != 0 ? a : r */
    r = mask_mov_i64(t, mask, r);
    return r;
}
IPP_OWN_DEFN(fesm2, fesm2_sub_norder_norm, (const fesm2 a, const fesm2 b)) {
    const fesm2 zero = setzero_i64();
    const fesm2 N    = FESM2_LOADU(nsm2_x1);
    /* r = a - b */
    fesm2 r = sub_i64(a, b);
    r       = ifma_norm52(r);

    /* t = r + M */
    fesm2 t = add_i64(r, N);
    t       = ifma_lnorm52(t);

    /* lt = r < 0 */
    const mask8 lt   = cmp_i64_mask(zero, srli_i64(r, DIGIT_SIZE_52 - 1), _MM_CMPINT_LT);
    const mask8 mask = (mask8)((mask8)0 - ((lt >> 4) & 1));
    /* mask != 0 ? t : r */
    r = mask_mov_i64(r, mask, t);

    return r;
}

IPP_OWN_DEFN(fesm2, fesm2_fast_reduction_norder, (const fesm2 a)) {
    const fesm2 zero = setzero_i64();
    const fesm2 N    = FESM2_LOADU(nsm2_x1);

    fesm2 r = sub_i64(a, N);
    r       = ifma_norm52(r);

    const mask8 lt   = cmp_i64_mask(zero, srli_i64(r, DIGIT_SIZE_52 - 1), _MM_CMPINT_LT);
    const mask8 mask = (mask8)((mask8)0 - ((lt >> 4) & 1));

    /* mask != 0 ? a : r */
    r = mask_mov_i64(r, mask, a);
    return r;
}

IPP_OWN_DEFN(fesm2, fesm2_to_mont_norder, (const fesm2 a)) {
    const fesm2 RR = FESM2_LOADU(nsm2_rr);
    const fesm2 r  = fesm2_mul_norder(a, RR);
    return ifma_lnorm52(r);
}

IPP_OWN_DEFN(fesm2, fesm2_from_mont_norder, (const fesm2 a)) {
    const fesm2 ONE = FESM2_LOADU(ones);
    fesm2 r         = fesm2_mul_norder(a, ONE);
    r               = ifma_lnorm52(r);
    r               = fesm2_fast_reduction_norder(r);
    return r;
}

__IPPCP_INLINE fesm2 mul_norder_norm(const fesm2 a, const fesm2 b) {
    const fesm2 r = fesm2_mul_norder(a, b);
    return ifma_lnorm52(r);
}

__IPPCP_INLINE fesm2 sqr_norder_norm(const fesm2 a) {
    const fesm2 r = fesm2_mul_norder(a, a);
    return ifma_lnorm52(r);
}

#define SIZE_TBL (16)

#define sqr(R, A)    (R) = sqr_norder_norm((A))
#define mul(R, A, B) (R) = mul_norder_norm((A), (B))

IPP_OWN_DEFN(fesm2, fesm2_inv_norder_norm, (const fesm2 z)) {

    const fesm2 r_norder = FESM2_LOADU(nsm2_r);
    int i;

    // pwr_z_Tbl[i][] = z^i, i=0,..,15
    __ALIGN64 fesm2 pwr_z_Tbl[SIZE_TBL];

    pwr_z_Tbl[0] = r_norder;
    pwr_z_Tbl[1] = z;

    for (i = 2; i < SIZE_TBL; i += 2) {
        sqr(pwr_z_Tbl[i], pwr_z_Tbl[i / 2]);
        mul(pwr_z_Tbl[i + 1], pwr_z_Tbl[i], z);
    }

    // pwr = (nsm2-2) in big endian
    const Ipp8u pwr[] = "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF"
                        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                        "\x72\x03\xDF\x6B\x21\xC6\x05\x2B"
                        "\x53\xBB\xF4\x09\x39\xD5\x41\x21";
    // init r = 1
    fesm2 r = pwr_z_Tbl[0];

    for (i = 0; i < 32; ++i) {
        const int v  = pwr[i];
        const int hi = (v >> 4) & 0xF;
        const int lo = v & 0xF;

        sqr(r, r);
        sqr(r, r);
        sqr(r, r);
        sqr(r, r);
        if (hi)
            mul(r, r, pwr_z_Tbl[hi]);
        sqr(r, r);
        sqr(r, r);
        sqr(r, r);
        sqr(r, r);
        if (lo)
            mul(r, r, pwr_z_Tbl[lo]);
    }
    return r;
}

#undef SIZE_TBL
#undef sqr
#undef mul

#endif // (_IPP32E >= _IPP32E_K1)
