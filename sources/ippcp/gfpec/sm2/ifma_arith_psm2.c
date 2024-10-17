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

#include "gfpec/sm2/ifma_arith_psm2.h"
#include "gfpec/sm2/ifma_defs_sm2.h"

/* modulus psm2 = 2^256 - 2^224 - 2^96 + 2^64 - 1 */
static const __ALIGN64 Ipp64u psm2_x1[PSM2_LEN52] = {
    0x000fffffffffffff, 0x000ff00000000fff, 0x000fffffffffffff, 0x000fffffffffffff, 0x0000fffffffeffff};

/* 4*p */
static const __ALIGN64 Ipp64u psm2_x4[PSM2_LEN52] = {
    0x000ffffffffffffc, 0x000fc00000003fff, 0x000fffffffffffff, 0x000fffffffffffff, 0x0003fffffffbffff};

/* to Montgomery conversion constant
 * rr = 2^((PSM2_LEN52*DIGIT_SIZE)*2) mod psm2
 */
/* rr = 2^(52*6*2) mod psm2 */
static const __ALIGN64 Ipp64u psm2_rr[PSM2_LEN52] = {
    0x0006000000070000, 0x000fffffd0000000, 0x00000400000003ff, 0x0000000000300000, 0x0000000800000003};

static const __ALIGN64 Ipp64u ones[PSM2_LEN52] = {
    0x1, 0x0, 0x0, 0x0, 0x0};


/* R = (A/2) mod M */
IPP_OWN_DEFN(fesm2, fesm2_div2_norm, (const fesm2 a)) {
    const fesm2 M    = FESM2_LOADU(psm2_x1);
    const fesm2 zero = setzero_i64();
    const fesm2 one  = set1_i64(1LL);

    const mask8 is_last_one = cmp_i64_mask(and_i64(a, one), zero, _MM_CMPINT_EQ);
    const mask8 mask        = (mask8)((is_last_one & 1) - 1);

    fesm2 r = mask_add_i64(a, mask, a, M);
    r       = ifma_lnorm52(r);

    /* 1-bit shift right */
    /* extract last bite + >> 64 */
    const mask64 mask_shift = 0xFFFFFFFF;
    const fesm2 idx_shift   = set_i64(0x0,                 //  0,  0,  0,  0,  0,  0,  0,  0
                                      0x3f3e3d3c3b3a3938,  // 63, 62, 61, 60, 59, 58, 57, 56
                                      0x3736353433323130,  // 55, 54, 53, 52, 51, 50, 49, 48
                                      0x2f2e2d2c2b2a2928,  // 47, 46, 45, 44, 43, 42, 41, 40
                                      0x2726252423222120,  // 39, 38, 37, 36, 35, 34, 33, 32
                                      0x1f1e1d1c1b1a1918,  // 31, 30, 29, 28, 27, 26, 25, 24
                                      0x1716151413121110,  // 23, 22, 21, 20, 19, 18, 17, 16
                                      0x0f0e0d0c0b0a0908); // 15, 14, 13, 12, 11, 10, 9, 8

    fesm2 shift_right = maskz_permutexvar_i8(mask_shift, idx_shift, and_i64(r, one));
    /* set last bit is first byte (52 radix) */
    shift_right = slli_i64(shift_right, DIGIT_SIZE_52 - 1);
    /* join first new bite */
    r = srli_i64(r, 1);          /* create slot by first bite 1111 -> 0111 */
    r = add_i64(r, shift_right); /* join first and other bite */

    return r;
}

IPP_OWN_DEFN(fesm2, fesm2_neg_norm, (const fesm2 a)) {
    const fesm2 M4 = FESM2_LOADU(psm2_x4);

    /* a == 0 ? 0xFF : 0 */
    const mask8 mask_zero = FESM2_IS_ZERO(a);

    /* r = 4*p - a */
    fesm2 r = mask_sub_i64(a, (mask8)(~mask_zero), M4, a);
    r       = ifma_norm52(r);
    return r;
}

#define MULT_ROUND(R, A, B, IDX)                                               \
    const fesm2 Bi##R##IDX     = permutexvar_i8(idx##IDX, (B));                \
    const fesm2 amBiLo##R##IDX = madd52lo_i64(zero, (A), Bi##R##IDX);          \
    fesm2 tr##R##IDX           = madd52hi_i64(zero, (A), Bi##R##IDX);          \
    {                                                                          \
        /* low */                                                              \
        (R)           = add_i64((R), amBiLo##R##IDX);                          \
        const fesm2 u = permutexvar_i8(idx0, (R)); /* u = R0 * 1 */            \
        tr##R##IDX    = madd52hi_i64(tr##R##IDX, M, u);                        \
        (R)           = madd52lo_i64((R), M, u);                               \
        /* shift */                                                            \
        const fesm2 carryone = maskz_srai_i64(maskone, (R), DIGIT_SIZE_52);    \
        tr##R##IDX           = add_i64(tr##R##IDX, carryone);                  \
        (R)                  = maskz_permutexvar_i8(mask_sr64, idx_sr64, (R)); \
        /* hi */                                                               \
        (R) = add_i64((R), tr##R##IDX);                                        \
    }

/* R = (A*B) - no normalization (in radix 2^52) */
IPP_OWN_DEFN(fesm2, fesm2_mul, (const fesm2 a, const fesm2 b)) {
    const fesm2 M       = FESM2_LOADU(psm2_x1); /* p */
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
     * a[] b[] - input data ((in radix 2^52)) m[] - module psm2
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

IPP_OWN_DEFN(void, fesm2_mul_dual,
             (fesm2 pr1[], const fesm2 a1, const fesm2 b1,
              fesm2 pr2[], const fesm2 a2, const fesm2 b2)) {
    const fesm2 M       = FESM2_LOADU(psm2_x1); /* p */
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

    fesm2 r1, r2;
    r1 = r2 = setzero_i64();
    /* PSM2
     * m' mod b = 1
     *
     * Algorithm
     * a[] b[] - input data ((in radix 2^52)) m[] - module psm2
     *
     * when u =  R[0]*m' mod b
     * 1) R = R + a[] * b[i] (lo)
     * 2) R = R + m[] * u    (lo)
     * 3) R = R >> 64
     * 4) R = R + a[] * b[i] (hi)
     * 5) R = R + m[] * u    (hi)
     */
    /* one round = O(32) */
    MULT_ROUND(r1, a1, b1, 0)
    MULT_ROUND(r2, a2, b2, 0)
    MULT_ROUND(r1, a1, b1, 1)
    MULT_ROUND(r2, a2, b2, 1)
    MULT_ROUND(r1, a1, b1, 2)
    MULT_ROUND(r2, a2, b2, 2)
    MULT_ROUND(r1, a1, b1, 3)
    MULT_ROUND(r2, a2, b2, 3)
    MULT_ROUND(r1, a1, b1, 4)
    MULT_ROUND(r2, a2, b2, 4)
    MULT_ROUND(r1, a1, b1, 5)
    MULT_ROUND(r2, a2, b2, 5)

    *pr1 = r1;
    *pr2 = r2;
    return;
}

IPP_OWN_DEFN(fesm2, fesm2_to_mont, (const fesm2 a)) {
    const fesm2 RR = FESM2_LOADU(psm2_rr);

    fesm2 r = fesm2_mul(a, RR);
    return ifma_lnorm52(r);
}

static fesm2 fesm2_fast_reduction(const fesm2 a) {
    const fesm2 M    = FESM2_LOADU(psm2_x1);
    const fesm2 zero = setzero_i64();

    /* r = a - M */
    fesm2 r = sub_i64(a, M);
    r       = ifma_norm52(r);

    /* 1 < 0 */
    const mask8 lt   = cmp_i64_mask(zero, srli_i64(r, DIGIT_SIZE_52 - 1), _MM_CMPINT_LT);
    const mask8 mask = (mask8)((mask8)0 - ((lt >> 4) & 1));

    /* mask != 0 ? a : r */
    r = mask_mov_i64(r, mask, a);
    return r;
}

IPP_OWN_DEFN(fesm2, fesm2_from_mont, (const fesm2 a)) {
    const fesm2 ONE = FESM2_LOADU(ones);

    /* from mont */
    fesm2 r = fesm2_mul(a, ONE);
    r       = ifma_lnorm52(r);
    r       = fesm2_fast_reduction(r);
    return r;
}

__IPPCP_INLINE fesm2 fesm2_mul_norm(const fesm2 a, const fesm2 b) {
    fesm2 r = fesm2_mul(a, b);
    return ifma_lnorm52(r);
}

__IPPCP_INLINE fesm2 fesm2_sqr_norm(const fesm2 a) {
    fesm2 r = fesm2_sqr(a);
    return ifma_lnorm52(r);
}

#define mul(R, A, B) (R) = fesm2_mul_norm((A), (B))
#define sqr(R, A)    (R) = fesm2_sqr_norm((A))
#define mul_dual(R1, A1, B1, R2, A2, B2)                  \
    fesm2_mul_dual(&(R1), (A1), (B1), &(R2), (A2), (B2)); \
    ifma_lnorm52_dual(&(R1), (R1), &(R2), (R2));

__IPPCP_INLINE fesm2 fesm2_sqr_ntimes(const fesm2 a, int n) {
    fesm2 r = a;
    for (; n > 0; --n)
        sqr(r, r);
    return r;
}

#define sqr_ntimes(R, A, N) (R) = fesm2_sqr_ntimes((A), (N))

IPP_OWN_DEFN(fesm2, fesm2_inv_norm, (const fesm2 z)) {

    fesm2 tmp1, tmp2, D, E, F;
    tmp1 = tmp2 = D = E = F = setzero_i64();
    fesm2 r;
    r = setzero_i64();

    sqr(tmp1, z);
    mul(F, tmp1, z);         /* F = z^3 */
    sqr_ntimes(tmp2, F, 2);  /* tmp2 = z^0xC */
                             /**/
    mul_dual(D, tmp2, z,     /* D = z^0xD */
             E, tmp2, tmp1); /* E = z^0xE */
    mul(F, tmp2, F);         /* F = z^0xF */
                             /**/
    sqr_ntimes(tmp2, F, 4);  /* tmp2 = z^0xF0 */
                             /**/
    mul_dual(D, tmp2, D,     /* D = z^0xFD */
             E, tmp2, E);    /* E = z^0xFE */
    mul(F, tmp2, F);         /* F = z^0xFF */
                             /**/
    sqr_ntimes(tmp2, F, 8);  /* tmp2 = z^0xFF00 */
    mul_dual(D, tmp2, D,     /* D = z^0xFFFD */
             E, tmp2, E);    /* E = z^0xFFFE */
    mul(F, tmp2, F);         /* F = z^0xFFFF */
                             /**/
    sqr_ntimes(tmp2, F, 16); /* tmp2 = z^0xFFFF0000 */
    mul_dual(D, tmp2, D,     /* D = z^0xFFFFFFFD */
             E, tmp2, E);    /* E = z^0xFFFFFFFE */
    mul(F, tmp2, F);         /* F = z^0xFFFFFFFF */
                             /**/
                             /**/
    /* z ^ FFFFFFFE 00000000 */
    sqr_ntimes(r, E, 32);
    /* z ^ FFFFFFFE FFFFFFFF */
    mul(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF 00000000 */
    sqr_ntimes(r, r, 32);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF */
    mul(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF 00000000 */
    sqr_ntimes(r, r, 32);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF */
    mul(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 00000000 */
    sqr_ntimes(r, r, 32);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF */
    mul(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 00000000 */
    sqr_ntimes(r, r, 64);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF */
    mul(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF 00000000 */
    sqr_ntimes(r, r, 32);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFD */
    mul(r, r, D);
    return r;
}

IPP_OWN_DEFN(fesm2, fesm2_convert_radix64_radix52, (const Ipp64u* a)) {
    /* load mask to register */
    const mask8 mask_load  = 0x0F;
    const fesm2 mask_rad52 = set1_i64(DIGIT_MASK_52);
    /* set data */
    const fesm2 idx16       = set_i64(0x001f001f00170016,  // 31, 31, 23, 22,
                                      0x0016001500140013,  // 22, 21, 20, 19,
                                      0x0013001200110010,  // 19, 18, 17, 16,
                                      0x0010000f000e000d,  // 16, 15, 14, 13,
                                      0x000c000b000a0009,  // 12, 11, 10,  9,
                                      0x0009000800070006,  //  9,  8,  7,  6,
                                      0x0006000500040003,  //  6,  5,  4,  3,
                                      0x0003000200010000); //  3,  2,  1,  0
    const fesm2 shift_right = set_i64(12LL, 8LL, 4LL, 0LL, 12LL, 8LL, 4LL, 0LL);

    fesm2 r = maskz_loadu_i64(mask_load, a);
    r       = permutexvar_i16(idx16, r);
    r       = srlv_i64(r, shift_right);
    r       = and_i64(mask_rad52, r);
    return r;
}

IPP_OWN_DEFN(void, fesm2_convert_radix52_radix64, (Ipp64u * out, const fesm2 a)) {
    /* mask store */
    const mask8 mask_store = 0x0F;
    const fesm2 shift_left = set_i64(4LL, 0LL, 4LL, 0LL, 4LL, 0LL, 4LL, 0LL);
    const fesm2 idx_up8    = set_i64(0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
                                     0x3f3f3f3f3e3d3c3b,  // {63,63,63,63,62,61,60,59}
                                     0x3737363534333231,  // {55,55,54,53,52,51,50,49}
                                     0x302e2d2c2b2a2928,  // {48,46,45,44,43,42,41,40}
                                     0x1f1f1f1f1f1f1e1d,  // {31,31,31,31,31,31,30,29}
                                     0x1717171716151413,  // {23,23,23,23,22,21,20,19}
                                     0x0f0f0f0e0d0c0b0a,  // {15,15,15,14,13,12,11,10}
                                     0x0706050403020100); // { 7, 6, 5, 4, 3, 2, 1, 0}

    const fesm2 idx_down8 = set_i64(0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
                                    0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
                                    0x3a39383737373737,  // {58,57,56,55,55,55,55,55}
                                    0x2727272727272726,  // {39,39,39,39,39,39,39,38}
                                    0x2524232221201f1f,  // {37,36,35,34,33,32,31,31}
                                    0x1c1b1a1918171717,  // {28,27,26,25,24,23,23,23}
                                    0x1211100f0f0f0f0f,  // {18,17,16,15,15,15,15,15}
                                    0x0908070707070707); // { 9, 8, 7, 7, 7, 7, 7, 7}

    fesm2 r = a;

    r       = sllv_i64(r, shift_left);
    fesm2 T = permutexvar_i8(idx_up8, r);
    r       = permutexvar_i8(idx_down8, r);
    r       = or_i64(r, T);
    mask_storeu_i64(out, mask_store, r);
    return;
}

#endif // (_IPP32E >= _IPP32E_K1)
