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

#include "gfpec/ecnist/ifma_arith_p521.h"
/*
// EC NIST-P521 prime base point order
// in 2^52 radix
*/
static const __ALIGN64 Ipp64u n521_x1[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x000fb71e91386409,
     0x000b8899c47aebb6,
     0x000709a5d03bb5c9,
     0x000966b7fcc0148f },
   { 0x000a51868783bf2f,
     0x000fffffffffffff,
     0x000fffffffffffff,
     0x000fffffffffffff },
   { 0x000fffffffffffff,
     0x000fffffffffffff,
     0x0000000000000001,
     0x0000000000000000 }
};

static const __ALIGN64 Ipp64u n521_k0 = 0x000f5ccd79a995c7;

/* to Montgomery conversion constant
// rr = 2^((P521_LEN52*DIGIT_SIZE)*2) mod n521
*/
static const __ALIGN64 Ipp64u n521_rr[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x0003b4d7a5b140ce,
     0x000cb0bf26c55bf9,
     0x00037e5396c67ee9,
     0x0002bd1c80cf7b13 },
   { 0x00073cbe28f15e41,
     0x000dd6e23d82e49c,
     0x0003d142b7756e3e,
     0x00061a8e567bccff },
   { 0x00092d0d455bcc6d,
     0x000383d2d8e03d14,
     0x0000000000000000,
     0x0000000000000000 }
};

/* ifma_tomont52_n521_(1) */
static const __ALIGN64 Ipp64u n521_r[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x0008000000000000,
     0x00082470b763cdfb,
     0x00023bb31dc28a24,
     0x00047b2d17e2251b },
   { 0x00034ca4019ff5b8,
     0x0002d73cbc3e2068,
     0x0000000000000000,
     0x0000000000000000 },
   { 0x0000000000000000,
     0x0000000000000000,
     0x0000000000000000,
     0x0000000000000000 }
};

#define group_madd52hi_i64(R, A, B, C)                                \
   FE521_LO(R)  = m256_madd52hi_i64(FE521_LO(A), FE521_LO(B), (C));   \
   FE521_MID(R) = m256_madd52hi_i64(FE521_MID(A), FE521_MID(B), (C)); \
   FE521_HI(R)  = m256_madd52hi_i64(FE521_HI(A), FE521_HI(B), (C))

#define group_madd52lo_i64(R, A, B, C)                                \
   FE521_LO(R)  = m256_madd52lo_i64(FE521_LO(A), FE521_LO(B), (C));   \
   FE521_MID(R) = m256_madd52lo_i64(FE521_MID(A), FE521_MID(B), (C)); \
   FE521_HI(R)  = m256_madd52lo_i64(FE521_HI(A), FE521_HI(B), (C))

#define NEW_MUL_ROUND(R, A, IDX8, B)                                                    \
   const m256i Bi##R##IDX8 = m256_permutexvar_i8((IDX8), (B));                          \
   fe521 amBiLo##R##IDX8, tr##R##IDX8;                                                  \
   /* (lo/hi) a[]*b[i] */                                                               \
   FE521_LO(amBiLo##R##IDX8)  = m256_madd52lo_i64(zero, FE521_LO((A)), (Bi##R##IDX8));  \
   FE521_MID(amBiLo##R##IDX8) = m256_madd52lo_i64(zero, FE521_MID((A)), (Bi##R##IDX8)); \
   FE521_HI(amBiLo##R##IDX8)  = m256_madd52lo_i64(zero, FE521_HI((A)), (Bi##R##IDX8));  \
   FE521_LO(tr##R##IDX8)      = m256_madd52hi_i64(zero, FE521_LO((A)), (Bi##R##IDX8));  \
   FE521_MID(tr##R##IDX8)     = m256_madd52hi_i64(zero, FE521_MID((A)), (Bi##R##IDX8)); \
   FE521_HI(tr##R##IDX8)      = m256_madd52hi_i64(zero, FE521_HI((A)), (Bi##R##IDX8));  \
   {                                                                                    \
      /* R = R + a[]*b[i](lo) */                                                        \
      fe521_add_no_red(R, R, amBiLo##R##IDX8);                                          \
      /* u = R[0] * 1 */                                                                \
      const m256i R0 = m256_permutexvar_i8(idx0, FE521_LO((R)));                        \
      const m256i u  = m256_madd52lo_i64(zero, R0, K0);                                 \
      /* R = R + m[]*u (lo/hi) */                                                       \
      group_madd52hi_i64(tr##R##IDX8, tr##R##IDX8, N, u);                               \
      group_madd52lo_i64(R, R, N, u);                                                   \
      /* get carry low + add hi compute */                                              \
      const m256i carryone  = m256_maskz_srai_i64(0x1, FE521_LO(R), DIGIT_SIZE_52);     \
      FE521_LO(tr##R##IDX8) = m256_add_i64(FE521_LO(tr##R##IDX8), carryone);            \
      /* shift */                                                                       \
      FE521_LO(R)  = m256_alignr_i64(FE521_MID(R), FE521_LO(R), 1);                     \
      FE521_MID(R) = m256_alignr_i64(FE521_HI(R), FE521_MID(R), 1);                     \
      FE521_HI(R)  = m256_maskz_permutexvar_i8(mask_sr64, idx_sr64, FE521_HI(R));       \
      /* add hi compute */                                                              \
      fe521_add_no_red(R, R, tr##R##IDX8);                                              \
   }

IPP_OWN_DEFN(void, ifma_amm52_n521, (fe521 pr[], const fe521 a, const fe521 b))
{
   /* k0 */
   const m256i K0 = m256_set1_i64(n521_k0);
   fe521 N;
   FE521_LOADU(N, n521_x1);
   const m256i zero = m256_setzero_i64();
   /* chunk2 shift bit >> 64 */
   const mask32 mask_sr64 = 0x00FFFFFF;
   const m256i idx_sr64   = m256_set_i8(0, 0, 0, 0, 0, 0, 0, 0,
                                      31, 30, 29, 28, 27, 26, 25, 24,
                                      23, 22, 21, 20, 19, 18, 17, 16,
                                      15, 14, 13, 12, 11, 10, 9, 8);

   // IDX
   const m256i idx0 = m256_set_i8(REPL4(7, 6, 5, 4, 3, 2, 1, 0));
   const m256i idx1 = m256_set_i8(REPL4(15, 14, 13, 12, 11, 10, 9, 8));
   const m256i idx2 = m256_set_i8(REPL4(23, 22, 21, 20, 19, 18, 17, 16));
   const m256i idx3 = m256_set_i8(REPL4(31, 30, 29, 28, 27, 26, 25, 24));

   const m256i idx4 = m256_set_i8(REPL4(7, 6, 5, 4, 3, 2, 1, 0));
   const m256i idx5 = m256_set_i8(REPL4(15, 14, 13, 12, 11, 10, 9, 8));
   const m256i idx6 = m256_set_i8(REPL4(23, 22, 21, 20, 19, 18, 17, 16));
   const m256i idx7 = m256_set_i8(REPL4(31, 30, 29, 28, 27, 26, 25, 24));

   const m256i idx8  = m256_set_i8(REPL4(7, 6, 5, 4, 3, 2, 1, 0));
   const m256i idx9  = m256_set_i8(REPL4(15, 14, 13, 12, 11, 10, 9, 8));
   const m256i idx10 = m256_set_i8(REPL4(23, 22, 21, 20, 19, 18, 17, 16));

   fe521 r;
   FE521_SET(r) = m256_setzero_i64();
   NEW_MUL_ROUND(r, a, idx0, FE521_LO(b))
   NEW_MUL_ROUND(r, a, idx1, FE521_LO(b))
   NEW_MUL_ROUND(r, a, idx2, FE521_LO(b))
   NEW_MUL_ROUND(r, a, idx3, FE521_LO(b))
   NEW_MUL_ROUND(r, a, idx4, FE521_MID(b))
   NEW_MUL_ROUND(r, a, idx5, FE521_MID(b))
   NEW_MUL_ROUND(r, a, idx6, FE521_MID(b))
   NEW_MUL_ROUND(r, a, idx7, FE521_MID(b))
   NEW_MUL_ROUND(r, a, idx8, FE521_HI(b))
   NEW_MUL_ROUND(r, a, idx9, FE521_HI(b))
   NEW_MUL_ROUND(r, a, idx10, FE521_HI(b))

   ifma_lnorm52_p521(&r, r);

   FE521_COPY(*pr, r);
   return;
}

#undef group_madd52hi_i64
#undef group_madd52lo_i64
#undef NEW_MUL_ROUND

IPP_OWN_DEFN(void, ifma_add52_n521, (fe521 pr[], const fe521 a, const fe521 b))
{
   const m256i zero = m256_setzero_i64();
   fe521 N;
   FE521_LOADU(N, n521_x1);

   /* r = a + b */
   fe521 r;
   fe521_add_no_red(r, a, b);
   ifma_lnorm52_p521(&r, r);

   /* t = r - N */
   fe521 t;
   fe521_sub_no_red(t, r, N);
   ifma_norm52_p521(&t, t);

   /* lt = t < 0 */
   const mask8 lt   = m256_cmp_i64_mask(zero, m256_srli_i64(FE521_HI(t), DIGIT_SIZE_52 - 1), _MM_CMPINT_LT);
   const mask8 mask = (mask8)((mask8)0 - ((lt >> 2) & 1));

   /* mask != 0 ? a : r */
   FE521_MASK_MOV(r, t, mask, r);
   FE521_COPY(*pr, r);
   return;
}

IPP_OWN_DEFN(void, ifma_tomont52_n521, (fe521 pr[], const fe521 a))
{
   fe521 RR;
   FE521_LOADU(RR, n521_rr);
   ifma_amm52_n521(pr, a, RR);
   return;
}

IPP_OWN_DEFN(void, ifma_fastred52_n521, (fe521 pr[], const fe521 a))
{
   fe521 N;
   FE521_LOADU(N, n521_x1);
   const m256i zero = m256_setzero_i64();

   fe521 r;
   fe521_sub_no_red(r, a, N);
   ifma_norm52_p521(&r, r);

   const mask8 lt   = m256_cmp_i64_mask(zero, m256_srli_i64(FE521_HI(r), DIGIT_SIZE_52 - 1), _MM_CMPINT_LT);
   const mask8 mask = (mask8)((mask8)0 - ((lt >> 2) & 1));

   /* mask != 0 ? a : r */
   FE521_MASK_MOV(r, r, mask, a);
   FE521_COPY(*pr, r);
   return;
}

IPP_OWN_DEFN(void, ifma_frommont52_n521, (fe521 pr[], const fe521 a))
{
   fe521 ONE;
   FE521_LOADU(ONE, P521R1_ONE52);
   ifma_amm52_n521(pr, a, ONE);
   ifma_fastred52_n521(pr, *pr);
   return;
}

static void ifma_ams52_n521(fe521 pr[], const fe521 a)
{
   ifma_amm52_n521(pr, a, a);
}

#define mul(R, A, B) ifma_amm52_n521(&(R), (A), (B))
#define sqr(R, A) ifma_ams52_n521(&(R), (A))

/* r = base^(2^n) */
__IPPCP_INLINE IPP_OWN_DEFN(void, ifma_ams52_p521_ntimes, (fe521 pr[], const fe521 a, int n))
{
   fe521 r;
   FE521_COPY(r, a);
   for (; n > 0; --n)
      sqr(r, r);
   FE521_COPY(*pr, r);
   return;
}

#define sqr_ntimes(R, A, N) ifma_ams52_p521_ntimes(&(R), (A), (N))

IPP_OWN_DEFN(void, ifma_aminv52_n521, (fe521 pr[], const fe521 z))
{
   Ipp32u i;
   fe521 n521r1_r;

   FE521_LOADU(n521r1_r, n521_r);

   // pwr_z_Tbl[i][] = z^i, i=0,..,15
   __ALIGN64 fe521 pwr_z_Tbl[16];
   __ALIGN64 fe521 lexp;

   FE521_COPY(pwr_z_Tbl[0], n521r1_r);
   FE521_COPY(pwr_z_Tbl[1], z);

   for (i = 2u; i < 16u; i += 2u) {
      sqr(pwr_z_Tbl[i], pwr_z_Tbl[i / 2u]);
      mul(pwr_z_Tbl[i + 1u], pwr_z_Tbl[i], z);
   }

   // pwr = (n521-2) in big endian
   const Ipp8u pwr[] = "\x1\xFF"
                       "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                       "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                       "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                       "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFA"
                       "\x51\x86\x87\x83\xBF\x2F\x96\x6B"
                       "\x7F\xCC\x01\x48\xF7\x09\xA5\xD0"
                       "\x3B\xB5\xC9\xB8\x89\x9C\x47\xAE"
                       "\xBB\x6F\xB7\x1E\x91\x38\x64\x07";

   /*
    // process 25 low bytes of the exponent: :FA 51 86 ... 64 07"
    */
   /* init result */
   FE521_COPY(lexp, n521r1_r);

   for (i = 33u; i < sizeof(pwr) - 1u; ++i) {
      const int v  = pwr[i];
      const int hi = (v >> 4) & 0xF;
      const int lo = v & 0xF;

      sqr(lexp, lexp);
      sqr(lexp, lexp);
      sqr(lexp, lexp);
      sqr(lexp, lexp);
      if (hi)
         mul(lexp, lexp, pwr_z_Tbl[hi]);
      sqr(lexp, lexp);
      sqr(lexp, lexp);
      sqr(lexp, lexp);
      sqr(lexp, lexp);
      if (lo)
         mul(lexp, lexp, pwr_z_Tbl[lo]);
   }

   /*
    // process high part of the exponent: "0x1 0xffffffffffffffff 0xffffffffffffffff 0xffffffffffffffff 0xffffffffffffffff"
    */
   fe521 u, v;
   FE521_SET(u) = FE521_SET(v) = m256_setzero_i64();

   FE521_COPY(u, pwr_z_Tbl[15]); /* u = z^0xF */
                                 /**/
   sqr_ntimes(v, u, 4);          /* v = (z^0xF)^(2^4) = z^(0xF0) */
   mul(u, v, u);                 /* u = z^0xF0 * z^(0xF) = z^(0xFF) */
                                 /**/
   sqr_ntimes(v, u, 8);          /* v = (z^0xFF)^(2^8) = z^(0xFF00) */
   mul(u, v, u);                 /* u = z^0xFF00 * z^(0xFF) = z^(0xFFFF) */
                                 /**/
   sqr_ntimes(v, u, 16);         /* v = (z^0xFFFF)^(2^16) = z^(0xFFFF0000) */
   mul(u, v, u);                 /* u = z^0xFFFF0000 * z^(0xFFFF) = z^(0xFFFFFFFF) */
                                 /**/
   sqr_ntimes(v, u, 32);         /* v = (z^0xFFFFFFFF)^(2^32) = z^(0xFFFFFFFF00000000) */
   mul(u, v, u);                 /* u = z^0xFFFFFFFF00000000 * z^(0xFFFFFFFF) = z^(0xFFFFFFFFFFFFFFFF) */
                                 /**/
   sqr_ntimes(v, z, 64);         /**/
   mul(v, v, u);                 /* v = z^(0x1.FFFFFFFFFFFFFFFF) */
                                 /**/
   sqr_ntimes(v, v, 64);         /**/
   mul(v, v, u);                 /* v = z^(0x1.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF) */
                                 /**/
   sqr_ntimes(v, v, 64);         /**/
   mul(v, v, u);                 /* v = z^(0x1.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF) */
                                 /**/
   sqr_ntimes(v, v, 64);         /**/
   mul(v, v, u);                 /* v = z^(0x1.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF) */

   /* combine low and high results */
   sqr_ntimes(v, v, 64 * 4 + 8); /* u = z^(0x1.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.00.0000000000000000.0000000000000000.0000000000000000.0000000000000000) */
   mul(*pr, v, lexp);            /* r = z^(0x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFA.51868783BF2F966B.7FCC0148F709A5D0.3BB5C9B8899C47AE.BB6FB71E91386407) */
   return;
}

#undef mul
#undef sqr
#undef sqr_ntimes

#endif // (_IPP32E >= _IPP32E_K1)
