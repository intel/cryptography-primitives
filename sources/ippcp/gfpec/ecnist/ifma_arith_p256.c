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

#include "gfpec/ecnist/ifma_arith_p256.h"
#include "gfpec/ecnist/ifma_defs.h"

#define LEN52 (5 + 3) /* 5 digits + 3 zero padding */

/* Modulus p256r1 */
static const __ALIGN64 Ipp64u p256_x1[LEN52] = {
   0x000fffffffffffff, 0x00000fffffffffff, 0x0000000000000000, 0x0000001000000000, 0x0000ffffffff0000, 0x0, 0x0, 0x0
};

/* Scaled modulus 4*p256r1 */
static const __ALIGN64 Ipp64u p256_x4[LEN52] = {
   0x000ffffffffffffc, 0x00003fffffffffff, 0x0000000000000000, 0x0000004000000000, 0x0003fffffffc0000, 0x0, 0x0, 0x0
};

/* To Montgomery domain conversion constant
 *
 * The extended Montgomery domain here with R = 2^(6*52) instead of 2^(5*62) is
 * chosen to use NRMM field multiplication routine in the sequence of EC group
 * operations  (point multiplication on scalar / addition) without modulo
 * reductions in the field addition (see Chapter 4 in "Enhanced Montgomery
 * Multiplication" DOI:10.1155/2008/583926).  According to the paper the chosen
 * |s| in NRMM^s(a,b) shall be equal to n + 2*kmax, with kmax = 4 for EC group
 * operations, so s = 264.  5 digits capacity is only 260 bits, so purely IFMA-based
 * implementation shall use 6 digits.
 *
 * rr = 2^((52*6))*2) mod p256
 */
static const __ALIGN64 Ipp64u p256_rr6[LEN52] = {
   0x0002fffffffdffff, 0x0000100050000000, 0x000ffd0000000500, 0x0000000fff9fffff, 0x0000fff9fffefffe, 0x0, 0x0, 0x0
};

#if 0
/*
 * rr = 2^((52*5))*2) mod p256
 */
static const __ALIGN64 Ipp64u p256_rr5[LEN52] = {
   0x0000000000000300, 0x000ffffffff00000, 0x000ffffefffffffb, 0x000fdfffffffffff, 0x0000000004ffffff, 0x0, 0x0, 0x0
};
#endif

static const __ALIGN64 Ipp64u ones[LEN52] = {
   1, 0, 0, 0, 0, 0, 0, 0
};

#define MUL_RED_ROUND(R, A, B, IDX)                                      \
   {                                                                     \
      const m512 Bi = permutexvar_i8(idx_b##IDX, (B));                   \
      m512 Rlo      = madd52lo_i64(zero, (A), Bi);                       \
      m512 tmp      = madd52hi_i64(zero, (A), Bi);                       \
                                                                         \
      (R) = add_i64((R), Rlo);                                           \
      /* broadcast R[0] */                                               \
      const m512 R0 = permutexvar_i8(idx_b0, (R));                       \
      (R)           = madd52lo_i64((R), M, R0);                          \
      tmp           = madd52hi_i64(tmp, M, R0);                          \
      /* shift */                                                        \
      const m512 carry = maskz_srli_i64(maskone, (R), DIGIT_SIZE);       \
      tmp              = add_i64(tmp, carry);                            \
      (R)              = maskz_permutexvar_i8(mask_sr64, idx_sr64, (R)); \
      /* hi */                                                           \
      (R) = add_i64((R), tmp);                                           \
   }

/* R = (A*B) - no normalization radix 52 */
IPP_OWN_DEFN(m512, ifma_amm52_p256, (const m512 a, const m512 b))
{
   const m512 M        = loadu_i64(p256_x1);
   const m512 zero     = setzero_i64();
   const mask8 maskone = 0x1;

   /* Index broadcast */
   const m512 idx_b0 = set_i64(REPL8(0x0706050403020100)); // 7,   6,  5,  4,  3,  2,  1,  0
   const m512 idx_b1 = set_i64(REPL8(0x0f0e0d0c0b0a0908)); // 15, 14, 13, 12, 11, 10,  9,  8
   const m512 idx_b2 = set_i64(REPL8(0x1716151413121110)); // 23, 22, 21, 20, 19, 18, 17, 16
   const m512 idx_b3 = set_i64(REPL8(0x1f1e1d1c1b1a1918)); // 31, 30, 29, 28, 27, 26, 25, 24
   const m512 idx_b4 = set_i64(REPL8(0x2726252423222120)); // 39, 38, 37, 36, 35, 34, 33, 32
   const m512 idx_b5 = set_i64(REPL8(0x2f2e2d2c2b2a2928)); // 47, 46, 45, 44, 43, 42, 41, 40

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

   MUL_RED_ROUND(r, a, b, 0)
   MUL_RED_ROUND(r, a, b, 1)
   MUL_RED_ROUND(r, a, b, 2)
   MUL_RED_ROUND(r, a, b, 3)
   MUL_RED_ROUND(r, a, b, 4)
   MUL_RED_ROUND(r, a, b, 5)

   return r;
}

IPP_OWN_DEFN(void, ifma_amm52_dual_p256, (m512 * r1, const m512 a1, const m512 b1, m512 *r2, const m512 a2, const m512 b2))
{
   const m512 M        = loadu_i64(p256_x1);
   const m512 zero     = setzero_i64();
   const mask8 maskone = 0x1;

   /* Index broadcast */
   const m512 idx_b0 = set_i64(REPL8(0x0706050403020100)); // 7,   6,  5,  4,  3,  2,  1,  0
   const m512 idx_b1 = set_i64(REPL8(0x0f0e0d0c0b0a0908)); // 15, 14, 13, 12, 11, 10,  9,  8
   const m512 idx_b2 = set_i64(REPL8(0x1716151413121110)); // 23, 22, 21, 20, 19, 18, 17, 16
   const m512 idx_b3 = set_i64(REPL8(0x1f1e1d1c1b1a1918)); // 31, 30, 29, 28, 27, 26, 25, 24
   const m512 idx_b4 = set_i64(REPL8(0x2726252423222120)); // 39, 38, 37, 36, 35, 34, 33, 32
   const m512 idx_b5 = set_i64(REPL8(0x2f2e2d2c2b2a2928)); // 47, 46, 45, 44, 43, 42, 41, 40

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

   m512 t1 = setzero_i64();
   m512 t2 = setzero_i64();

   MUL_RED_ROUND(t1, a1, b1, 0)
   MUL_RED_ROUND(t2, a2, b2, 0)

   MUL_RED_ROUND(t1, a1, b1, 1)
   MUL_RED_ROUND(t2, a2, b2, 1)

   MUL_RED_ROUND(t1, a1, b1, 2)
   MUL_RED_ROUND(t2, a2, b2, 2)

   MUL_RED_ROUND(t1, a1, b1, 3)
   MUL_RED_ROUND(t2, a2, b2, 3)

   MUL_RED_ROUND(t1, a1, b1, 4)
   MUL_RED_ROUND(t2, a2, b2, 4)

   MUL_RED_ROUND(t1, a1, b1, 5)
   MUL_RED_ROUND(t2, a2, b2, 5)

   *r1 = t1;
   *r2 = t2;
}

/* R = (A*B) with norm */
__IPPCP_INLINE m512 ifma_amm52_p256_norm(const m512 a, const m512 b)
{
   m512 r = ifma_amm52_p256(a, b);
   return ifma_lnorm52(r);
}

/* R = (A*A) with norm */
__IPPCP_INLINE m512 ifma_ams52_p256_norm(const m512 a)
{
   return ifma_amm52_p256_norm(a, a);
}

/* R = (A/2) */
IPP_OWN_DEFN(m512, ifma_half52_p256, (const m512 a))
{
   const m512 M    = loadu_i64(p256_x1);
   const m512 zero = setzero_i64();
   const m512 one  = set1_i64(1LL);

   const mask8 is_last_one = cmp_i64_mask(and_i64(a, one), zero, _MM_CMPINT_EQ);
   const mask8 mask        = (mask8)((is_last_one & 1) - 1);

   const mask64 mask_shift = 0x00ffffffffffffff;
   const m512 idx_shift    = set_i64(0x0,               //  0,  0,  0,  0,  0,  0,  0,  0
                                  0x3f3e3d3c3b3a3938,  // 63, 62, 61, 60, 59, 58, 57, 56
                                  0x3736353433323130,  // 55, 54, 53, 52, 51, 50, 49, 48
                                  0x2f2e2d2c2b2a2928,  // 47, 46, 45, 44, 43, 42, 41, 40
                                  0x2726252423222120,  // 39, 38, 37, 36, 35, 34, 33, 32
                                  0x1f1e1d1c1b1a1918,  // 31, 30, 29, 28, 27, 26, 25, 24
                                  0x1716151413121110,  // 23, 22, 21, 20, 19, 18, 17, 16
                                  0x0f0e0d0c0b0a0908); // 15, 14, 13, 12, 11, 10, 9, 8

   m512 r = mask_add_i64(a, mask, a, M);
   r      = ifma_lnorm52(r);

   m512 leftBit = maskz_permutexvar_i8(mask_shift, idx_shift, and_i64(r, one));
   leftBit      = slli_i64(leftBit, DIGIT_SIZE - 1);
   r            = srli_i64(r, 1);
   r            = add_i64(r, leftBit);

   return r;
}

IPP_OWN_DEFN(m512, ifma_neg52_p256, (const m512 a))
{
   const m512 M4 = loadu_i64(p256_x4);

   /* a == 0 ? 0xFF : 0 */
   const mask8 mask_zero = is_zero_i64(a);

   /* r = 4*p - a */
   m512 r = mask_sub_i64(a, ~mask_zero, M4, a);
   r      = ifma_norm52(r);
   return r;
}


static m512 mod_reduction_p256(const m512 a)
{
   const m512 M    = loadu_i64(p256_x1);
   const m512 zero = setzero_i64();

   /* r = a - M */
   m512 r = sub_i64(a, M);
   r      = ifma_norm52(r);

   /* 1 < 0 */
   const mask8 lt   = cmp_i64_mask(zero, srli_i64(r, DIGIT_SIZE - 1), _MM_CMPINT_LT);
   const mask8 mask = check_bit(lt, 4); // check sign in 5th digit

   /* mask != 0 ? a : r */
   r = mask_mov_i64(r, mask, a);
   return r;
}

/* to Montgomery domain */
IPP_OWN_DEFN(m512, ifma_tomont52_p256, (const m512 a))
{
   return ifma_amm52_p256_norm(a, loadu_i64(p256_rr6));
}

/* from Montgomery domain */
IPP_OWN_DEFN(m512, ifma_frommont52_p256, (const m512 a))
{
   m512 r = ifma_amm52_p256_norm(a, loadu_i64(ones));
   r      = mod_reduction_p256(r);
   return r;
}

#define sqr(R, A) (R) = ifma_ams52_p256_norm((A))
#define mul(R, A, B) (R) = ifma_amm52_p256_norm((A), (B));

__IPPCP_INLINE m512 ifma_ams52_p256_ntimes(m512 a, Ipp32s n)
{
   for (; n > 0; --n)
      sqr(a, a);
   return a;
}

#define sqr_ntimes(R, A, N) (R) = ifma_ams52_p256_ntimes((A), (N))

/* R = 1/z */
IPP_OWN_DEFN(m512, ifma_aminv52_p256, (const m512 z))
{
   __ALIGN64 m512 tmp1;
   __ALIGN64 m512 tmp2;

   /* Each eI holds z^(2^I-1) */
   __ALIGN64 m512 e2;
   __ALIGN64 m512 e4;
   __ALIGN64 m512 e8;
   __ALIGN64 m512 e16;
   __ALIGN64 m512 e32;
   __ALIGN64 m512 e64;

   /* tmp1 = z^(2^1) */
   sqr(tmp1, z);
   /* e2 = tmp1 = tmp1 * z = z^(2^2 - 2^0) */
   mul(tmp1, tmp1, z);
   e2 = tmp1;

   /* tmp1 = tmp1^2 = z^(2^2 - 2^0)*2 = z^(2^3 - 2^1) */
   sqr(tmp1, tmp1);
   /* tmp1 = tmp1^2 = z^(2^3 - 2^1)*2 = z^(2^4 - 2^2) */
   sqr(tmp1, tmp1);
   /* e4 = tmp1 = tmp1*e2 = z^(2^4 - 2^2) * z^(2^2 - 2^0) = z^(2^4 - 2^2 + 2^2 - 2^0) = z^(2^4 - 2^0)*/
   mul(tmp1, tmp1, e2);
   e4 = tmp1;

   /* tmp1 = tmp1^2 = z^(2^4 - 2^0)*2 = z^(2^5 - 2^1) */
   sqr(tmp1, tmp1);
   /* tmp1 = tmp1^2 = z^(2^5 - 2^1)*2 = z^(2^6 - 2^2) */
   sqr(tmp1, tmp1);
   /* tmp1 = tmp1^2 = z^(2^6 - 2^2)*2 = z^(2^7 - 2^3) */
   sqr(tmp1, tmp1);
   /* tmp1 = tmp1^2 = z^(2^7 - 2^3)*2 = z^(2^8 - 2^4) */
   sqr(tmp1, tmp1);
   /* e8 = tmp1 = tmp1*e4 = z^(2^8 - 2^4) * z^(2^4 - 2^0) = z^(2^8 - 2^4 + 2^4 - 2^0) = z^(2^8 - 2^0)*/
   mul(tmp1, tmp1, e4);
   e8 = tmp1;

   /* tmp1 = tmp1^(2^8) = z^(2^8 - 2^0)*2^8 = z^(2^16 - 2^8) */
   sqr_ntimes(tmp1, tmp1, 8);

   /* e16 = tmp1 = tmp1*e8 = z^(2^16 - 2^8) * z^(2^8 - 2^0) = z^(2^16 - 2^8 + 2^8 - 2^0) = z^(2^16 - 2^0)*/
   mul(tmp1, tmp1, e8);
   e16 = tmp1;

   /* tmp1 = tmp1^(2^16) = z^(2^16 - 2^0)*2^16 = z^(2^32 - 2^16) */
   sqr_ntimes(tmp1, tmp1, 16);

   /* e32 = tmp1 = tmp1*e16 = z^(2^32 - 2^16) * z^(2^16 - 2^0) = z^(2^32 - 2^16 + 2^16 - 2^0) = z^(2^32 - 2^0)*/
   mul(tmp1, tmp1, e16);
   e32 = tmp1;

   /* e64 = tmp1 = tmp1^(2^32) = z^(2^32 - 2^0)*2^32 = z^(2^64 - 2^32) */
   sqr_ntimes(tmp1, tmp1, 32);

   e64 = tmp1;
   /* tmp1 = tmp1*z = z^(2^64 - 2^32) * z = z^(2^64 - 2^32 + 2^0)*/
   mul(tmp1, tmp1, z);

   /* tmp1 = tmp1^(2^192) = z^(2^64 - 2^32 + 2^0)*2^192 = z^(2^256 - 2^224 + 2^192) */
   sqr_ntimes(tmp1, tmp1, 192);

   /* tmp2 = e64*e32 = z^(2^64 - 2^32) * z^(2^32 - 2^0) = z^(2^64 - 2^32 + 2^32 - 2^0) = z^(2^64 - 2^0)*/
   mul(tmp2, e64, e32);

   /* tmp2 = tmp2^(2^16) = z^(2^64 - 2^0)*2^16 = z^(2^80 - 2^16) */
   sqr_ntimes(tmp2, tmp2, 16);

   /* tmp2 = tmp2*e16 = z^(2^80 - 2^16) * z^(2^16 - 2^0) = z^(2^80 - 2^16 + 2^16 - 2^0) = z^(2^80 - 2^0)*/
   mul(tmp2, tmp2, e16);

   /* tmp2 = tmp2^(2^8) = z^(2^80 - 2^0)*2^8 = z^(2^88 - 2^8) */
   sqr_ntimes(tmp2, tmp2, 8);

   /* tmp2 = tmp2*e8 = z^(2^88 - 2^8) * z^(2^8 - 2^0) = z^(2^88 - 2^8 + 2^8 - 2^0) = z^(2^88 - 2^0)*/
   mul(tmp2, tmp2, e8);

   /* tmp2 = tmp2^(2^4) = z^(2^88 - 2^0)*2^4 = z^(2^92 - 2^4) */
   sqr_ntimes(tmp2, tmp2, 4);

   /* tmp2 = tmp2*e4 = z^(2^92 - 2^4) * z^(2^4 - 2^0) = z^(2^92 - 2^4 + 2^4 - 2^0) = z^(2^92 - 2^0)*/
   mul(tmp2, tmp2, e4);

   /* tmp2 = tmp2^2 = z^(2^92 - 2^0)*2^1 = z^(2^93 - 2^1) */
   sqr(tmp2, tmp2);
   /* tmp2 = tmp2^2 = z^(2^93 - 2^1)*2^1 = z^(2^94 - 2^2) */
   sqr(tmp2, tmp2);
   /* tmp2 = tmp2*e2 = z^(2^94 - 2^2) * z^(2^2 - 2^0) = z^(2^94 - 2^2 + 2^2 - 2^0) = z^(2^94 - 2^0)*/
   mul(tmp2, tmp2, e2);
   /* tmp2 = tmp2^2 = z^(2^94 - 2^0)*2^1 = z^(2^95 - 2^1) */
   sqr(tmp2, tmp2);
   /* tmp2 = tmp2^2 = z^(2^95 - 2^1)*2^1 = z^(2^96 - 2^2) */
   sqr(tmp2, tmp2);
   /* tmp2 = tmp2*z = z^(2^96 - 2^2) * z = z^(2^96 - 2^2 + 1) = z^(2^96 - 3) */
   mul(tmp2, tmp2, z);

   /* r = tmp1*tmp2 = z^(2^256 - 2^224 + 2^192) * z^(2^96 - 3) = z^(2^256 - 2^224 + 2^192 + 2^96 - 3) */
   m512 r = setzero_i64();
   mul(r, tmp1, tmp2);

   return r;
}

#undef sqr
#undef mul
#undef sqr_ntimes

IPP_OWN_DEFN(m512, convert_radix_to_52x5, (const Ipp64u *arad64))
{
   const m512 mask_rad52 = set1_i64(DIGIT_MASK);

   const m512 idx16 = set_i64(
       0x0019001800170016,  // 25, 24, 23, 22,
       0x0016001500140013,  // 22, 21, 20, 19,
       0x0013001200110010,  // 19, 18, 17, 16,
       0x0010000f000e000d,  // 16, 15, 14, 13,
       0x000c000b000a0009,  // 12, 11, 10,  9,
       0x0009000800070006,  //  9,  8,  7,  6,
       0x0006000500040003,  //  6,  5,  4,  3,
       0x0003000200010000); //  3,  2,  1,  0

   const __m512i shiftR = set_i64(
       12, 8, 4, 0,
       12, 8, 4, 0);

   m512 r = maskz_loadu_i64(0xf, arad64); // load 4 digits
   r      = permutexvar_i16(idx16, r);
   r      = srlv_i64(r, shiftR);
   r      = and_i64(mask_rad52, r);
   return r;
}

IPP_OWN_DEFN(void, convert_radix_to_64x4, (Ipp64u * rrad64, const m512 arad52))
{
   const m512 shiftL = set_i64(
       4, 0, 4, 0,
       4, 0, 4, 0);
   const m512 perm1 = set_i64(
       0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
       0x3f3f3f3f3e3d3c3b,  // {63,63,63,63,62,61,60,59}
       0x3737363534333231,  // {55,55,54,53,52,51,50,49}
       0x302e2d2c2b2a2928,  // {48,46,45,44,43,42,41,40}
       0x1f1f1f1f1f1f1e1d,  // {31,31,31,31,31,31,30,29}
       0x1717171716151413,  // {23,23,23,23,22,21,20,19}
       0x0f0f0f0e0d0c0b0a,  // {15,15,15,14,13,12,11,10}
       0x0706050403020100); // { 7, 6, 5, 4, 3, 2, 1, 0}

   const m512 perm2 = set_i64(
       0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
       0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
       0x3a39383737373737,  // {58,57,56,55,55,55,55,55}
       0x2727272727272726,  // {39,39,39,39,39,39,39,38}
       0x2524232221201f1f,  // {37,36,35,34,33,32,31,31}
       0x1c1b1a1918171717,  // {28,27,26,25,24,23,23,23}
       0x1211100f0f0f0f0f,  // {18,17,16,15,15,15,15,15}
       0x0908070707070707); // { 9, 8, 7, 7, 7, 7, 7, 7}

   m512 r = arad52;
   r      = sllv_i64(r, shiftL);
   m512 T = permutexvar_i8(perm1, r);
   r      = permutexvar_i8(perm2, r);
   r      = or_i64(r, T);
   mask_storeu_i64(rrad64, 0xf, r); // store 4 digits
}

#endif // #if (_IPP32E >= _IPP32E_K1)
