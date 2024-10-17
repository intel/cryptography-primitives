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

#include "gfpec/ecnist/ifma_arith_n384.h"
#include "gfpec/ecnist/ifma_arith_p384.h"
#include "gfpec/ecnist/ifma_defs.h"

/* Constants */
#define LEN52 (NUMBER_OF_DIGITS(384, 52))

/*
 * EC NIST-P384 base point order
 * in 2^52 radix
 */
static const __ALIGN64 Ipp64u n384_x1[LEN52] = {
   0x000c196accc52973, 0x000b248b0a77aece, 0x0004372ddf581a0d, 0x000ffffc7634d81f, 0x000fffffffffffff, 0x000fffffffffffff, 0x000fffffffffffff, 0x00000000000fffff
};

/* k0 = (-1/n384) mod 2^52 */
static const __ALIGN64 Ipp64u n384_k0 = 0x00046089e88fdc45;

/* r = 2^((52*8)) mod n384 */
static const __ALIGN64 Ipp64u n384_r[LEN52] = {
   0x000ad68d00000000, 0x000851313e695333, 0x0007e5f24db74f58, 0x000b27e0bc8d220a, 0x000000000000389c, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000
};

/* To Montgomery conversion constant
 * rr = 2^((52*8)*2) mod n384
 */
static const __ALIGN64 Ipp64u n384_rr[LEN52] = {
   0x00034124f50ddb2d, 0x000c974971bd0d8d, 0x0002118942bfd3cc, 0x0009f43be8072178, 0x0005bf030606de60, 0x0000d49174aab1cc, 0x000b7a28266895d4, 0x000000000003fb05
};

static const __ALIGN64 Ipp64u ones[LEN52] = {
   0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

#define MULT_ROUND(R, A, B, IDX)                                            \
   const m512 Bi##R##IDX     = permutexvar_i8(idx_b##IDX, (B));             \
   const m512 amBiLo##R##IDX = madd52lo_i64(zero, (A), Bi##R##IDX);         \
   m512 tr##R##IDX           = madd52hi_i64(zero, (A), Bi##R##IDX);         \
   {                                                                        \
      /* low */                                                             \
      (R)           = add_i64((R), amBiLo##R##IDX);                         \
      const m512 R0 = permutexvar_i8(idx_b0, (R));                          \
      const m512 u  = madd52lo_i64(zero, K0, R0);                           \
      tr##R##IDX    = madd52hi_i64(tr##R##IDX, N, u);                       \
      (R)           = madd52lo_i64((R), N, u);                              \
      /* shift */                                                           \
      const m512 carryone = maskz_srai_i64(maskone, (R), DIGIT_SIZE);       \
      tr##R##IDX          = add_i64(tr##R##IDX, carryone);                  \
      (R)                 = maskz_permutexvar_i8(mask_sr64, idx_sr64, (R)); \
      /* hi */                                                              \
      (R) = add_i64((R), tr##R##IDX);                                       \
   }

/* R = (A*B) - no normalization (in radix 2^52) */
IPP_OWN_DEFN(m512, ifma_amm52_n384, (const m512 a, const m512 b))
{
   const m512 N        = loadu_i64(n384_x1); /* n */
   const m512 K0       = set1_i64(n384_k0);  /* k0 */
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
   /* N384
     * m' mod b = 46089e88fdc45
     *
     * Algorithm
     * a[] b[] - input data ((in radix 2^52)) m[] - module n384
     *
     * where u =  R[0]*m' mod b
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

   r = ifma_lnorm52(r);

   return r;
}

IPP_OWN_DEFN(m512, ifma_add52_n384, (const m512 a, const m512 b))
{
   const m512 zero = setzero_i64();
   const m512 N    = loadu_i64(n384_x1);

   /* r = a + b */
   m512 r = add_i64(a, b);
   r      = ifma_lnorm52(r);

   /* t = r - N */
   m512 t = sub_i64(r, N);
   t      = ifma_norm52(t);

   /* lt = t < 0 */
   const mask8 lt   = cmp_i64_mask(zero, srli_i64(t, DIGIT_SIZE - 1), _MM_CMPINT_LT);
   const mask8 mask = check_bit(lt, 7);
   /* mask != 0 ? r : t */
   r = mask_mov_i64(t, mask, r);

   return r;
}

static m512 ifma_ams52_n384(const m512 a)
{
   return ifma_amm52_n384(a, a);
}

IPP_OWN_DEFN(m512, ifma_tomont52_n384, (const m512 a))
{
   const m512 RR = loadu_i64(n384_rr);
   return ifma_amm52_n384(a, RR);
}

IPP_OWN_DEFN(m512, ifma_fastred52_n384, (const m512 a))
{
   const m512 N    = loadu_i64(n384_x1);
   const m512 zero = setzero_i64();

   /* r = a - N */
   m512 r = sub_i64(a, N);
   r      = ifma_norm52(r);

   /* 1 < 0 */
   const mask8 lt   = cmp_i64_mask(zero, srli_i64(r, DIGIT_SIZE - 1), _MM_CMPINT_LT);
   const mask8 mask = check_bit(lt, 7);

   /* mask != 0 ? a : r */
   r = mask_mov_i64(r, mask, a);
   return r;
}

IPP_OWN_DEFN(m512, ifma_frommont52_n384, (const m512 a))
{
   const m512 ONE = loadu_i64(ones);
   m512 r         = ifma_amm52_n384(a, ONE);
   return ifma_fastred52_n384(r);
}

#define sqr(R, A) (R) = ifma_ams52_n384((A))
#define mul(R, A, B) (R) = ifma_amm52_n384((A), (B))

/*
 * computes r = 1/z = z^(n384-2) mod n384
 *
 * note: z in in Montgomery domain
 *       r in Montgomery domain
 */
__IPPCP_INLINE m512 ifma_ams52_n384_ntimes(const m512 a, int n)
{
   m512 r = a;
   for (; n > 0; --n) {
      sqr(r, r);
   }
   return r;
}

#define sqr_ntimes(R, A, N) (R) = ifma_ams52_n384_ntimes((A), (N))

IPP_OWN_DEFN(m512, ifma_aminv52_n384, (const m512 z))
{

   const m512 r_norder = loadu_i64(n384_r);

   /* table pwr_z_Tbl[i] = z^i, i = 0,..,15 */
   __ALIGN64 m512 pwr_z_tbl[16];
   m512 lexp;
   lexp = setzero_i64();

   /* fill table */
   pwr_z_tbl[0] = r_norder;
   pwr_z_tbl[1] = z;
   for (int i = 2; i < 16; i += 2) {
      sqr(pwr_z_tbl[i], pwr_z_tbl[i / 2]);
      mul(pwr_z_tbl[i + 1], pwr_z_tbl[i], z);
   }

   // pwr = (n384-2) in big endian
   const Ipp8u pwr[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                       "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                       "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                       "\xC7\x63\x4D\x81\xF4\x37\x2D\xDF"
                       "\x58\x1A\x0D\xB2\x48\xB0\xA7\x7A"
                       "\xEC\xEC\x19\x6A\xCC\xC5\x29\x71";

   /*
     * process low part of the exponent: "0xc7634d81f4372ddf 0x581a0db248b0a77a 0xecec196accc52973"
     */
   /* init result */
   lexp = r_norder;
   for (Ipp32u i = 24u; i < (sizeof(pwr) - 1u); ++i) {
      const int v  = (int)(pwr[i]);
      const int hi = (v >> 4) & 0xF;
      const int lo = v & 0xF;

      sqr(lexp, lexp);
      sqr(lexp, lexp);
      sqr(lexp, lexp);
      sqr(lexp, lexp);
      if (0 != hi)
         mul(lexp, lexp, pwr_z_tbl[hi]);

      sqr(lexp, lexp);
      sqr(lexp, lexp);
      sqr(lexp, lexp);
      sqr(lexp, lexp);
      if (0 != lo)
         mul(lexp, lexp, pwr_z_tbl[lo]);
   }
   m512 u, v;
   u = v = setzero_i64();

   sqr(v, z);            /* v = z^2 */
   mul(u, v, z);         /* u = z^2 * z = z^3  */
                         /**/
   sqr_ntimes(v, u, 2);  /* v = (z^3)^(2^2) = z^12 */
   mul(u, v, u);         /* u = z^12 * z^3 = z^15 = z^(0xF) */
                         /**/
   sqr_ntimes(v, u, 4);  /* v = (z^0xF)^(2^4) = z^(0xF0) */
   mul(u, v, u);         /* u = z^0xF0 * z^(0xF) = z^(0xFF) */
                         /**/
   sqr_ntimes(v, u, 8);  /* v = (z^0xFF)^(2^8) = z^(0xFF00) */
   mul(u, v, u);         /* u = z^0xFF00 * z^(0xFF) = z^(0xFFFF) */
                         /**/
   sqr_ntimes(v, u, 16); /* v = (z^0xFFFF)^(2^16) = z^(0xFFFF0000) */
   mul(u, v, u);         /* u = z^0xFFFF0000 * z^(0xFFFF) = z^(0xFFFFFFFF) */
                         /**/
   sqr_ntimes(v, u, 32); /* v = (z^0xFFFFFFFF)^(2^32) = z^(0xFFFFFFFF00000000) */
   mul(u, v, u);         /* u = z^0xFFFFFFFF00000000 * z^(0xFFFFFFFF) = z^(0xFFFFFFFFFFFFFFFF) */
                         /**/
   sqr_ntimes(v, u, 64); /**/
   mul(v, v, u);         /* v = z^(0xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF) */
                         /**/
   sqr_ntimes(v, v, 64); /**/
   mul(v, v, u);         /* v = z^(0xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF) */

   /* combine low and high results */
   sqr_ntimes(v, v, 64 * 3); /* u = z^(0xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.0000000000000000.0000000000000000.0000000000000000) */
   m512 r = setzero_i64();   /**/
   mul(r, v, lexp);          /* r = z^(0xFFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.c7634d81f4372ddf.581a0db248b0a77a.ecec196accc52973) */
   return r;
}

#undef sqr
#undef mul
#undef sqr_ntimes

#endif // (_IPP32E >= _IPP32E_K1)
