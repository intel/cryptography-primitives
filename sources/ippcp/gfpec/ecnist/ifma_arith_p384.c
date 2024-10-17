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

#include "gfpec/ecnist/ifma_arith_p384.h"
#include "gfpec/ecnist/ifma_defs.h"

#define LEN52 (NUMBER_OF_DIGITS(384, 52))

/* p384r1: p = 2^384 - 2^128 - 2^96 + 2^32 - 1 */
static const __ALIGN64 Ipp64u p384_x1[LEN52] = {
   0x00000000FFFFFFFF, 0x000FF00000000000, 0x000FFFFFFEFFFFFF, 0x000FFFFFFFFFFFFF, 0x000FFFFFFFFFFFFF, 0x000FFFFFFFFFFFFF, 0x000FFFFFFFFFFFFF, 0x00000000000FFFFF
};

/* modulus 4*p */
static const __ALIGN64 Ipp64u p384_x4[LEN52] = {
   0x00000003FFFFFFFC, 0x000FC00000000000, 0x000FFFFFFBFFFFFF, 0x000FFFFFFFFFFFFF, 0x000FFFFFFFFFFFFF, 0x000FFFFFFFFFFFFF, 0x000FFFFFFFFFFFFF, 0x00000000003FFFFF
};

/* to Montgomery conversion constant
 * rr = 2^((P384_LEN52*DIGIT_SIZE)*2) mod p384
 */
static const __ALIGN64 Ipp64u p384_rr[LEN52] = {
   0x0000000000000000, 0x000FE00000001000, 0x0000000000FFFFFF, 0x0000000000000020, 0x0000FFFFFFFE0000, 0x0000000020000000, 0x0000000000000100, 0x0000000000000000
};

static const __ALIGN64 Ipp64u ones[LEN52] = {
   1, 0, 0, 0, 0, 0, 0, 0
};

/* R = (A/2) */
IPP_OWN_DEFN(m512, ifma_half52_p384, (const m512 a))
{
   const m512 M    = loadu_i64(p384_x1);
   const m512 zero = setzero_i64();
   const m512 one  = set1_i64(1LL);

   const mask8 is_last_one = cmp_i64_mask(and_i64(a, one), zero, _MM_CMPINT_EQ);
   const mask8 mask        = (mask8)((is_last_one & 1) - 1);

   m512 r = mask_add_i64(a, mask, a, M);
   r      = ifma_lnorm52(r);

   /* 1-bit shift right */
   /* extract last bit + >> 64 */
   const mask64 mask_shift = 0x00ffffffffffffff;
   const m512 idx_shift    = set_i64(0x0,               //  0,  0,  0,  0,  0,  0,  0,  0
                                  0x3f3e3d3c3b3a3938,  // 63, 62, 61, 60, 59, 58, 57, 56
                                  0x3736353433323130,  // 55, 54, 53, 52, 51, 50, 49, 48
                                  0x2f2e2d2c2b2a2928,  // 47, 46, 45, 44, 43, 42, 41, 40
                                  0x2726252423222120,  // 39, 38, 37, 36, 35, 34, 33, 32
                                  0x1f1e1d1c1b1a1918,  // 31, 30, 29, 28, 27, 26, 25, 24
                                  0x1716151413121110,  // 23, 22, 21, 20, 19, 18, 17, 16
                                  0x0f0e0d0c0b0a0908); // 15, 14, 13, 12, 11, 10, 9, 8

   m512 shift_right = maskz_permutexvar_i8(mask_shift, idx_shift, and_i64(r, one));
   /* set last bit is first bit (52 radix) */
   shift_right = slli_i64(shift_right, DIGIT_SIZE - 1);
   /* join first new bit */
   r = srli_i64(r, 1);          /* create slot by first bit 1111 -> 0111 */
   r = add_i64(r, shift_right); /* join first and other bit */

   return r;
}

IPP_OWN_DEFN(m512, ifma_neg52_p384, (const m512 a))
{
   const m512 M4 = loadu_i64(p384_x4);

   /* a == 0 ? 0xFF : 0 */
   const mask8 mask_zero = is_zero_i64(a);

   /* r = 4*p - a */
   m512 r = mask_sub_i64(a, ~mask_zero, M4, a);
   r      = ifma_norm52(r);
   return r;
}

#define MULT_ROUND(R, A, B, IDX)                                            \
   const m512 Bi##R##IDX     = permutexvar_i8(idx_b##IDX, (B));             \
   const m512 amBiLo##R##IDX = madd52lo_i64(zero, (A), Bi##R##IDX);         \
   m512 tr##R##IDX           = madd52hi_i64(zero, (A), Bi##R##IDX);         \
   {                                                                        \
      /* low */                                                             \
      (R)           = add_i64((R), amBiLo##R##IDX);                         \
      const m512 R0 = permutexvar_i8(idx_b0, (R));                          \
      const m512 u  = add_i64(slli_i64(R0, 32), R0);                        \
      tr##R##IDX    = madd52hi_i64(tr##R##IDX, M, u);                       \
      (R)           = madd52lo_i64((R), M, u);                              \
      /* shift */                                                           \
      const m512 carryone = maskz_srai_i64(maskone, (R), DIGIT_SIZE);       \
      tr##R##IDX          = add_i64(tr##R##IDX, carryone);                  \
      (R)                 = maskz_permutexvar_i8(mask_sr64, idx_sr64, (R)); \
      /* hi */                                                              \
      (R) = add_i64((R), tr##R##IDX);                                       \
   }

/* gueron data */
/* R = (A*B) - no normalization radix 52 */
IPP_OWN_DEFN(m512, ifma_amm52_p384, (const m512 a, const m512 b))
{
   const m512 M        = loadu_i64(p384_x1); /* p */
   const m512 zero     = setzero_i64();
   const mask8 maskone = 0x1;

   /* Index broadcast */
   const m512 idx_b0 = set_i64(REPL8(0x0706050403020100)); // 7,   6,  5,  4,  3,  2,  1,  0
   const m512 idx_b1 = set_i64(REPL8(0x0f0e0d0c0b0a0908)); // 15, 14, 13, 12, 11, 10,  9,  8
   const m512 idx_b2 = set_i64(REPL8(0x1716151413121110)); // 23, 22, 21, 20, 19, 18, 17, 16
   const m512 idx_b3 = set_i64(REPL8(0x1f1e1d1c1b1a1918)); // 31, 30, 29, 28, 27, 26, 25, 24
   const m512 idx_b4 = set_i64(REPL8(0x2726252423222120)); // 39, 38, 37, 36, 35, 34, 33, 32
   const m512 idx_b5 = set_i64(REPL8(0x2f2e2d2c2b2a2928)); // 47, 46, 45, 44, 43, 42, 41, 40
   const m512 idx_b6 = set_i64(REPL8(0x3736353433323130)); // 55, 54, 53, 52, 51, 50, 49, 48
   const m512 idx_b7 = set_i64(REPL8(0x3f3e3d3c3b3a3938)); // 63, 62, 61, 60, 59, 58, 57, 56

   /* Mask to shift zmm register right on 64-bit */
   const mask64 mask_sr64 = 0x00ffffffffffffff;
   const m512 idx_sr64    = set_i64(0x0,            //  0,  0,  0,  0,  0,  0,  0,  0
                                 0x3f3e3d3c3b3a3938,  // 63, 62, 61, 60, 59, 58, 57, 56
                                 0x3736353433323130,  // 55, 54, 53, 52, 51, 50, 49, 48
                                 0x2f2e2d2c2b2a2928,  // 47, 46, 45, 44, 43, 42, 41, 40
                                 0x2726252423222120,  // 39, 38, 37, 36, 35, 34, 33, 32
                                 0x1f1e1d1c1b1a1918,  // 31, 30, 29, 28, 27, 26, 25, 24
                                 0x1716151413121110,  // 23, 22, 21, 20, 19, 18, 17, 16
                                 0x0f0e0d0c0b0a0908); // 15, 14, 13, 12, 11, 10, 9, 8

   m512 r = setzero_i64();
   /* P384
     * m' mod b = 2^32 + 1
     *
     * Algorithm
     * a[] b[] - input data ((in radix 2^52)) m[] - module p384
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
   MULT_ROUND(r, a, b, 6)
   MULT_ROUND(r, a, b, 7)

   return r;
}

IPP_OWN_DEFN(void, ifma_amm52_dual_p384, (m512 * pr1, const m512 a1, const m512 b1, m512 *pr2, const m512 a2, const m512 b2))
{
   const m512 M        = loadu_i64(p384_x1); /* p */
   const m512 zero     = setzero_i64();
   const mask8 maskone = 0x1;

   /* Index broadcast */
   const m512 idx_b0 = set_i64(REPL8(0x0706050403020100)); // 7,   6,  5,  4,  3,  2,  1,  0
   const m512 idx_b1 = set_i64(REPL8(0x0f0e0d0c0b0a0908)); // 15, 14, 13, 12, 11, 10,  9,  8
   const m512 idx_b2 = set_i64(REPL8(0x1716151413121110)); // 23, 22, 21, 20, 19, 18, 17, 16
   const m512 idx_b3 = set_i64(REPL8(0x1f1e1d1c1b1a1918)); // 31, 30, 29, 28, 27, 26, 25, 24
   const m512 idx_b4 = set_i64(REPL8(0x2726252423222120)); // 39, 38, 37, 36, 35, 34, 33, 32
   const m512 idx_b5 = set_i64(REPL8(0x2f2e2d2c2b2a2928)); // 47, 46, 45, 44, 43, 42, 41, 40
   const m512 idx_b6 = set_i64(REPL8(0x3736353433323130)); // 55, 54, 53, 52, 51, 50, 49, 48
   const m512 idx_b7 = set_i64(REPL8(0x3f3e3d3c3b3a3938)); // 63, 62, 61, 60, 59, 58, 57, 56

   /* Mask to shift zmm register right on 64-bit */
   const mask64 mask_sr64 = 0x00ffffffffffffff;
   const m512 idx_sr64    = set_i64(0x0,            //  0,  0,  0,  0,  0,  0,  0,  0
                                 0x3f3e3d3c3b3a3938,  // 63, 62, 61, 60, 59, 58, 57, 56
                                 0x3736353433323130,  // 55, 54, 53, 52, 51, 50, 49, 48
                                 0x2f2e2d2c2b2a2928,  // 47, 46, 45, 44, 43, 42, 41, 40
                                 0x2726252423222120,  // 39, 38, 37, 36, 35, 34, 33, 32
                                 0x1f1e1d1c1b1a1918,  // 31, 30, 29, 28, 27, 26, 25, 24
                                 0x1716151413121110,  // 23, 22, 21, 20, 19, 18, 17, 16
                                 0x0f0e0d0c0b0a0908); // 15, 14, 13, 12, 11, 10, 9, 8

   m512 r1 = setzero_i64();
   m512 r2 = setzero_i64();
   /* P384
     * m' mod b = 2^32 + 1
     *
     * Algorithm
     * a[] b[] - input data ((in radix 2^52)) m[] - module p384
     *
     * when u =  R[0]*m' mod b
     * 1) R = R + a[] * b[i] (lo)
     * 2) R = R + m[] * u    (lo)
     * 3) R = R >> 64
     * 4) R = R + a[] * b[i] (hi)
     * 5) R = R + m[] * u    (hi)
     */
   /* one round = O(32) */
   /* 0-1 */
   MULT_ROUND(r1, a1, b1, 0)
   MULT_ROUND(r1, a1, b1, 1)
   /* 0-1 */
   MULT_ROUND(r2, a2, b2, 0)
   MULT_ROUND(r2, a2, b2, 1)
   /* 2-3 */
   MULT_ROUND(r1, a1, b1, 2)
   MULT_ROUND(r1, a1, b1, 3)
   /* 2-3 */
   MULT_ROUND(r2, a2, b2, 2)
   MULT_ROUND(r2, a2, b2, 3)
   /* 4-5 */
   MULT_ROUND(r1, a1, b1, 4)
   MULT_ROUND(r1, a1, b1, 5)
   /* 4-5 */
   MULT_ROUND(r2, a2, b2, 4)
   MULT_ROUND(r2, a2, b2, 5)
   /* 6-7 */
   MULT_ROUND(r1, a1, b1, 6)
   MULT_ROUND(r1, a1, b1, 7)
   /* 6-7 */
   MULT_ROUND(r2, a2, b2, 6)
   MULT_ROUND(r2, a2, b2, 7)

   /* set out */
   *pr1 = r1;
   *pr2 = r2;
   return;
}

/* R = (A*B) with norm */
__IPPCP_INLINE m512 ifma_amm52_p384_norm(const m512 a, const m512 b)
{
   m512 r = ifma_amm52_p384(a, b);
   /* normalization */
   return ifma_lnorm52(r);
}

/* R = (A*A) with norm */
__IPPCP_INLINE m512 m512_sqr_norm(const m512 a)
{
   return ifma_amm52_p384_norm(a, a);
}

/* to Montgomery domain */
IPP_OWN_DEFN(m512, ifma_tomont52_p384, (const m512 a))
{
   const m512 RR = loadu_i64(p384_rr);
   return ifma_amm52_p384_norm(a, RR);
}

static m512 mod_reduction_p384(const m512 a)
{
   const m512 M    = loadu_i64(p384_x1);
   const m512 zero = setzero_i64();

   /* r = a - M */
   m512 r = sub_i64(a, M);
   r      = ifma_norm52(r);

   /* 1 < 0 */
   const mask8 lt   = cmp_i64_mask(zero, srli_i64(r, DIGIT_SIZE - 1), _MM_CMPINT_LT);
   const mask8 mask = check_bit(lt, 7);

   /* mask != 0 ? a : r */
   r = mask_mov_i64(r, mask, a);
   return r;
}

/* from Montgomery domain */
IPP_OWN_DEFN(m512, ifma_frommont52_p384, (const m512 a))
{
   const m512 one = loadu_i64(ones);

   /* from mont */
   m512 r = ifma_amm52_p384_norm(a, one);
   r      = mod_reduction_p384(r);
   return r;
}

#define sqr(R, A) (R) = m512_sqr_norm((A))
#define mul(R, A, B) (R) = ifma_amm52_p384_norm((A), (B));
#define mul_dual(R1, A1, B1, R2, A2, B2)                       \
   ifma_amm52_dual_p384(&(R1), (A1), (B1), &(R2), (A2), (B2)); \
   ifma_lnorm52_dual(&(R1), (R1), &(R2), (R2))

__IPPCP_INLINE m512 ifma_ams52_p384_ntimes(const m512 a, Ipp32s n)
{
   m512 r = a;
   for (; n > 0; --n)
      sqr(r, r);
   return r;
}

#define sqr_ntimes(R, A, N) (R) = ifma_ams52_p384_ntimes((A), (N))

/* R = 1/z */
IPP_OWN_DEFN(m512, ifma_aminv52_p384, (const m512 z))
{
   m512 u, v, zD, zE, zF;
   u = v = zD = zE = zF = setzero_i64();

   sqr(u, z);             /*  u = z^2 */
   mul(v, u, z);          /*  v = z^2 * z     = z^3  */
   sqr_ntimes(zF, v, 2);  /* zF = (z^3)^(2^2) = z^12 */
                          /**/
   mul(zD, zF, z);        /* zD = z^11 * z    = z^xD */
   mul_dual(zE, zF, u,    /* zE = z^11 * z^2  = z^xE */
            zF, zF, v);   /* zF = z^11 * z^3  = z^xF */
                          /**/
   sqr_ntimes(u, zF, 4);  /* u  = (z^xF)^(2^4)  = z^xF0 */
   mul_dual(zD, u, zD,    /* zD = z^xF0 * z^xD  = z^xFD */
            zE, u, zE);   /* zE = z^xF0 * z^xE  = z^xFE */
   mul(zF, u, zF);        /* zF = z^xF0 * z^xF  = z^xFF */
                          /**/
   sqr_ntimes(u, zF, 8);  /* u = (z^xFF)^(2^8)    = z^xFF00 */
   mul_dual(zD, u, zD,    /* zD = z^xFF00 * z^xFD = z^xFFFD */
            zE, u, zE);   /* zE = z^xFF00 * z^xFE = z^xFFFE */
   mul(zF, u, zF);        /* zF = z^xFF00 * z^xFF = z^xFFFF */
                          /**/
   sqr_ntimes(u, zF, 16); /* u = (z^xFFFF)^(2^16)       = z^xFFFF0000 */
   mul_dual(zD, u, zD,    /* zD = z^xFFFF0000 * z^xFFFD = z^xFFFFFFFD */
            zE, u, zE);   /* zE = z^xFFFF0000 * z^xFFFE = z^xFFFFFFFE */
   mul(zF, u, zF);        /* zF = z^xFFFF0000 * z^xFFFF = z^xFFFFFFFF */
                          /**/
   sqr_ntimes(u, zF, 32); /* u = (z^xFFFFFFFF)^(2^32)               = z^xFFFFFFFF00000000 */
   mul_dual(zE, u, zE,    /* zE = z^xFFFFFFFF00000000 * z^xFFFFFFFE = z^xFFFFFFFFFFFFFFFE */
            zF, u, zF);   /* zF = z^xFFFFFFFF00000000 * z^xFFFFFFFF = z^xFFFFFFFFFFFFFFFF */
   /* v =  z^xFFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFF
                = z^xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF */
   sqr_ntimes(v, zF, 64);
   mul(v, v, zF);
   /* v =  z^xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFF
                  = z^xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFFF */
   sqr_ntimes(v, v, 64);
   mul(v, v, zF);
   /* v =  z^xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFE
                = z^xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFE */
   sqr_ntimes(v, v, 64);
   mul(v, v, zE);
   /* v =  z^xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFE.0000000000000000 * z^xFFFFFFFF00000000
                = z^xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFE.FFFFFFFF00000000 */
   sqr_ntimes(v, v, 64);
   mul(v, v, u);
   /* r =  z^xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFE.FFFFFFFF00000000.0000000000000000 * z^xFFFFFFFD
                = z^xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFE.FFFFFFFF00000000.00000000FFFFFFFD */
   sqr_ntimes(v, v, 64);
   m512 r = setzero_i64();
   mul(r, v, zD);
   return r;
}

#undef sqr
#undef mul
#undef mul_dual
#undef sqr_ntimes

IPP_OWN_DEFN(m512, convert_radix_to_52x8, (const Ipp64u *arad64))
{
   /* load mask to register */
   const mask8 mask_load = 0x3f;
   const m512 mask_rad52 = set1_i64(DIGIT_MASK);
   /* set data */
   const m512 idx16       = set_i64(
       0x0019001800170016,  // 25, 24, 23, 22,
       0x0016001500140013,  // 22, 21, 20, 19,
       0x0013001200110010,  // 19, 18, 17, 16,
       0x0010000f000e000d,  // 16, 15, 14, 13,
       0x000c000b000a0009,  // 12, 11, 10,  9,
       0x0009000800070006,  //  9,  8,  7,  6,
       0x0006000500040003,  //  6,  5,  4,  3,
       0x0003000200010000); //  3,  2,  1,  0

   const m512 shift_right = set_i64(12LL, 8LL, 4LL, 0LL, 12LL, 8LL, 4LL, 0LL);

   m512 r = maskz_loadu_i64(mask_load, arad64);
   r      = permutexvar_i16(idx16, r);
   r      = srlv_i64(r, shift_right);
   r      = and_i64(mask_rad52, r);
   return r;
}

IPP_OWN_DEFN(void, convert_radix_to_64x6, (Ipp64u * rrad64, const m512 arad52))
{
   /* mask store */
   const mask8 mask_store = 0x3f;
   const m512 shift_left  = set_i64(4LL, 0LL, 4LL, 0LL, 4LL, 0LL, 4LL, 0LL);
   const m512 idx_up8     = set_i64(
       0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
       0x3f3f3f3f3e3d3c3b,  // {63,63,63,63,62,61,60,59}
       0x3737363534333231,  // {55,55,54,53,52,51,50,49}
       0x302e2d2c2b2a2928,  // {48,46,45,44,43,42,41,40}
       0x1f1f1f1f1f1f1e1d,  // {31,31,31,31,31,31,30,29}
       0x1717171716151413,  // {23,23,23,23,22,21,20,19}
       0x0f0f0f0e0d0c0b0a,  // {15,15,15,14,13,12,11,10}
       0x0706050403020100); // { 7, 6, 5, 4, 3, 2, 1, 0}

   const m512 idx_down8 = set_i64(
       0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
       0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
       0x3a39383737373737,  // {58,57,56,55,55,55,55,55}
       0x2727272727272726,  // {39,39,39,39,39,39,39,38}
       0x2524232221201f1f,  // {37,36,35,34,33,32,31,31}
       0x1c1b1a1918171717,  // {28,27,26,25,24,23,23,23}
       0x1211100f0f0f0f0f,  // {18,17,16,15,15,15,15,15}
       0x0908070707070707); // { 9, 8, 7, 7, 7, 7, 7, 7}

   m512 r = arad52;

   r      = sllv_i64(r, shift_left);
   m512 T = permutexvar_i8(idx_up8, r);
   r      = permutexvar_i8(idx_down8, r);
   r      = or_i64(r, T);
   mask_storeu_i64(rrad64, mask_store, r);
   return;
}

#endif // #if (_IPP32E >= _IPP32E_K1)
