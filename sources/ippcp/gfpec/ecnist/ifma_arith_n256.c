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

#include "gfpec/ecnist/ifma_arith_n256.h"
#include "gfpec/ecnist/ifma_arith_p256.h"
#include "gfpec/ecnist/ifma_defs.h"

/* Constants */
#define LEN52 (5 + 3) /* 5 digits + 3 zero padding */

/*
 * EC NIST-P256 base point order
 * in 2^52 radix
 */
static const __ALIGN64 Ipp64u n256_x1[LEN52] = {
   0x0009cac2fc632551, 0x000ada7179e84f3b, 0x000fffffffbce6fa, 0x0000000fffffffff, 0x0000ffffffff0000, 0x0, 0x0, 0x0
};

static const __ALIGN64 Ipp64u n256_x2[LEN52] = {
   0x00039585f8c64aa2, 0x0005b4e2f3d09e77, 0x000fffffff79cdf5, 0x0000001fffffffff, 0x0001fffffffe0000, 0x0, 0x0, 0x0
};

/* k0 = (-1/n256) mod 2^52 */
static const __ALIGN64 Ipp64u n256_k0 = 0x1c8aaee00bc4f;

/*
 * r = 2^((52*5)) mod n256
 */
static const __ALIGN64 Ipp64u n256_r[LEN52] = {
   0x000353d039cdaaf0, 0x000258e8617b0c46, 0x0000000004319055, 0x000fff0000000000, 0x00000000000fffff, 0x0, 0x0, 0x0
};

/* To Montgomery conversion constant
 * r = 2^((52*5)*2) mod n256
 */
static const __ALIGN64 Ipp64u n256_rr[LEN52] = {
   0x0005cc0dea6dc3ba, 0x000192a067d8a084, 0x000bec59615571bb, 0x0001fc245b2392b6, 0x0000e12d9559d956, 0x0, 0x0, 0x0
};

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
      const m512 Yi = madd52lo_i64(zero, k0, R0);                        \
      (R)           = madd52lo_i64((R), N, Yi);                          \
      tmp           = madd52hi_i64(tmp, N, Yi);                          \
      /* shift */                                                        \
      const m512 carry = maskz_srli_i64(maskone, (R), DIGIT_SIZE);       \
      tmp              = add_i64(tmp, carry);                            \
      (R)              = maskz_permutexvar_i8(mask_sr64, idx_sr64, (R)); \
      /* hi */                                                           \
      (R) = add_i64((R), tmp);                                           \
   }

/* R = (A*B) */
IPP_OWN_DEFN(m512, ifma_amm52_n256, (const m512 a, const m512 b))
{
   const m512 N        = loadu_i64(n256_x1); /* modulus */
   const m512 k0       = set1_i64(n256_k0);  /* k0 */
   const m512 zero     = setzero_i64();
   const mask8 maskone = 0x1;

   /* Index broadcast */
   const m512 idx_b0 = set_i64(REPL8(0x0706050403020100)); // 7,   6,  5,  4,  3,  2,  1,  0
   const m512 idx_b1 = set_i64(REPL8(0x0f0e0d0c0b0a0908)); // 15, 14, 13, 12, 11, 10,  9,  8
   const m512 idx_b2 = set_i64(REPL8(0x1716151413121110)); // 23, 22, 21, 20, 19, 18, 17, 16
   const m512 idx_b3 = set_i64(REPL8(0x1f1e1d1c1b1a1918)); // 31, 30, 29, 28, 27, 26, 25, 24
   const m512 idx_b4 = set_i64(REPL8(0x2726252423222120)); // 39, 38, 37, 36, 35, 34, 33, 32

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

   r = ifma_lnorm52(r);

   return r;
}

IPP_OWN_DEFN(m512, ifma_add52_n256, (const m512 a, const m512 b))
{
   const m512 zero = setzero_i64();
   const m512 Nx2  = loadu_i64(n256_x2);

   /* r = a + b */
   m512 r = add_i64(a, b);
   r      = ifma_lnorm52(r);

   /* t = r - N */
   m512 t = sub_i64(r, Nx2);
   t      = ifma_norm52(t);

   /* lt = t < 0 */
   const mask8 lt   = cmp_i64_mask(zero, srli_i64(t, DIGIT_SIZE - 1), _MM_CMPINT_LT);
   const mask8 mask = check_bit(lt, 4); // check sign in 5h digit
   /* mask != 0 ? r : t */
   r = mask_mov_i64(t, mask, r);

   return r;
}

static m512 ifma_ams52_n256(const m512 a)
{
   return ifma_amm52_n256(a, a);
}

IPP_OWN_DEFN(m512, ifma_fastred52_n256, (const m512 a))
{
   const m512 N    = loadu_i64(n256_x1);
   const m512 zero = setzero_i64();

   /* r = a - N */
   m512 r = sub_i64(a, N);
   r      = ifma_norm52(r);

   /* 1 < 0 */
   const mask8 lt   = cmp_i64_mask(zero, srli_i64(r, DIGIT_SIZE - 1), _MM_CMPINT_LT);
   const mask8 mask = check_bit(lt, 4); // check sign in 5th digit

   /* mask != 0 ? a : r */
   r = mask_mov_i64(r, mask, a);
   return r;
}

IPP_OWN_DEFN(m512, ifma_tomont52_n256, (const m512 a))
{
   return ifma_amm52_n256(a, loadu_i64(n256_rr));
}

IPP_OWN_DEFN(m512, ifma_frommont52_n256, (const m512 a))
{
   m512 r = ifma_amm52_n256(a, loadu_i64(ones));
   return ifma_fastred52_n256(r);
}

#define sqr(R, A) (R) = ifma_ams52_n256((A))
#define mul(R, A, B) (R) = ifma_amm52_n256((A), (B))

/*
 * computes r = 1/z = z^(n256-2) mod n256
 *
 * note: z in in Montgomery domain
 *       r in Montgomery domain
 */
__IPPCP_INLINE m512 ifma_ams52_n256_ntimes(const m512 a, int n)
{
   m512 r = a;
   for (; n > 0; --n) {
      sqr(r, r);
   }
   return r;
}

#define sqr_ntimes(R, A, N) (R) = ifma_ams52_n256_ntimes((A), (N))

/*
 * computes r = 1/z = z^(n256-2) mod n256
 *
 * note: z is in Montgomery domain
 *       (as soon mul() and sqr() below are amm-functions,
 *        the result is in Montgomery domain too)
 */

IPP_OWN_DEFN(m512, ifma_aminv52_n256, (const m512 z))
{
   const m512 r_n256 = loadu_i64(n256_r);
   int i;

   // pwr_z_Tbl[i][] = z^i, i=0,..,15
   __ALIGN64 m512 pwr_z_tbl[16];
   m512 r;

   pwr_z_tbl[0] = r_n256;
   pwr_z_tbl[1] = z;
   for (i = 2; i < 16; i += 2) {
      sqr(pwr_z_tbl[i], pwr_z_tbl[i / 2]);
      mul(pwr_z_tbl[i + 1], pwr_z_tbl[i], z);
   }

   // pwr = (n256-2) in big endian
   Ipp8u pwr[] = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00"
                 "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                 "\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84"
                 "\xF3\xB9\xCA\xC2\xFC\x63\x25\x4F";
   // init r = 1
   r = r_n256;

   for (i = 0; i < 32; i++) {
      int v  = pwr[i];
      int hi = (v >> 4) & 0xF;
      int lo = v & 0xF;

      sqr(r, r);
      sqr(r, r);
      sqr(r, r);
      sqr(r, r);
      if (hi)
         mul(r, r, pwr_z_tbl[hi]);
      sqr(r, r);
      sqr(r, r);
      sqr(r, r);
      sqr(r, r);
      if (lo)
         mul(r, r, pwr_z_tbl[lo]);
   }

   return r;
}

#undef sqr
#undef mul
#undef sqr_ntimes

#endif // (_IPP32E >= _IPP32E_K1)
