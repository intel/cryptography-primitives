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

#define NORM_LO_MID_ROUND(CARRY, RLO, RHI)                  \
   (CARRY) = m256_srai_i64((RLO), DIGIT_SIZE_52);           \
   (RLO)   = m256_and_i64((RLO), filt_rad52);               \
   (CARRY) = m256_permutexvar_i8(idx8_shuffle, (CARRY));    \
   (RHI)   = m256_mask_add_i64((RHI), 0x1, (RHI), (CARRY)); \
   (RLO)   = m256_mask_add_i64((RLO), 0xE, (RLO), (CARRY));

#define NORM_HI_ROUND(CARRY, RHI)                                        \
   (CARRY) = m256_maskz_srai_i64(0x7, (RHI), DIGIT_SIZE_52);             \
   (CARRY) = m256_maskz_permutexvar_i8(0xFFFF00, idx8_shuffle, (CARRY)); \
   (RHI)   = m256_add_i64(m256_and_i64((RHI), filt_rad52), (CARRY));

IPP_OWN_DEFN(void, ifma_norm52_p521, (fe521 pr[], const fe521 a))
{
   const m256i filt_rad52 = m256_set1_i64(DIGIT_MASK_52);

   fe521 r;
   FE521_COPY(r, a);

   const m256i idx8_shuffle = m256_set_i8(23, 22, 21, 20, 19, 18, 17, 16,
                                          15, 14, 13, 12, 11, 10, 9, 8,
                                          7, 6, 5, 4, 3, 2, 1, 0,
                                          31, 30, 29, 28, 27, 26, 25, 24);
   m256i carry;
   /* shift low carry */
   NORM_LO_MID_ROUND(carry, FE521_LO(r), FE521_MID(r))
   NORM_LO_MID_ROUND(carry, FE521_LO(r), FE521_MID(r))
   NORM_LO_MID_ROUND(carry, FE521_LO(r), FE521_MID(r))
   NORM_LO_MID_ROUND(carry, FE521_LO(r), FE521_MID(r))
   /* shift mid */
   NORM_LO_MID_ROUND(carry, FE521_MID(r), FE521_HI(r))
   NORM_LO_MID_ROUND(carry, FE521_MID(r), FE521_HI(r))
   NORM_LO_MID_ROUND(carry, FE521_MID(r), FE521_HI(r))
   NORM_LO_MID_ROUND(carry, FE521_MID(r), FE521_HI(r))
   /* shift hi */
   NORM_HI_ROUND(carry, FE521_HI(r))
   NORM_HI_ROUND(carry, FE521_HI(r))

   FE521_COPY(*pr, r);
   return;
}

IPP_OWN_DEFN(void, ifma_norm52_dual_p521,
             (fe521 pr1[], const fe521 a1,
              fe521 pr2[], const fe521 a2))
{
   const m256i filt_rad52 = m256_set1_i64(DIGIT_MASK_52);

   fe521 r1, r2;
   FE521_COPY(r1, a1);
   FE521_COPY(r2, a2);

   const m256i idx8_shuffle = m256_set_i8(23, 22, 21, 20, 19, 18, 17, 16,
                                          15, 14, 13, 12, 11, 10, 9, 8,
                                          7, 6, 5, 4, 3, 2, 1, 0,
                                          31, 30, 29, 28, 27, 26, 25, 24);
   m256i carry_1;
   m256i carry_2;
   /* shift low carry */
   NORM_LO_MID_ROUND(carry_1, FE521_LO(r1), FE521_MID(r1))
   NORM_LO_MID_ROUND(carry_2, FE521_LO(r2), FE521_MID(r2))
   NORM_LO_MID_ROUND(carry_1, FE521_LO(r1), FE521_MID(r1))
   NORM_LO_MID_ROUND(carry_2, FE521_LO(r2), FE521_MID(r2))
   NORM_LO_MID_ROUND(carry_1, FE521_LO(r1), FE521_MID(r1))
   NORM_LO_MID_ROUND(carry_2, FE521_LO(r2), FE521_MID(r2))
   NORM_LO_MID_ROUND(carry_1, FE521_LO(r1), FE521_MID(r1))
   NORM_LO_MID_ROUND(carry_2, FE521_LO(r2), FE521_MID(r2))
   /* shift mid */
   NORM_LO_MID_ROUND(carry_1, FE521_MID(r1), FE521_HI(r1))
   NORM_LO_MID_ROUND(carry_2, FE521_MID(r2), FE521_HI(r2))
   NORM_LO_MID_ROUND(carry_1, FE521_MID(r1), FE521_HI(r1))
   NORM_LO_MID_ROUND(carry_2, FE521_MID(r2), FE521_HI(r2))
   NORM_LO_MID_ROUND(carry_1, FE521_MID(r1), FE521_HI(r1))
   NORM_LO_MID_ROUND(carry_2, FE521_MID(r2), FE521_HI(r2))
   NORM_LO_MID_ROUND(carry_1, FE521_MID(r1), FE521_HI(r1))
   NORM_LO_MID_ROUND(carry_2, FE521_MID(r2), FE521_HI(r2))
   /* shift hi */
   NORM_HI_ROUND(carry_1, FE521_HI(r1))
   NORM_HI_ROUND(carry_2, FE521_HI(r2))
   NORM_HI_ROUND(carry_1, FE521_HI(r1))
   NORM_HI_ROUND(carry_2, FE521_HI(r2))

   FE521_COPY(*pr1, r1);
   FE521_COPY(*pr2, r2);
   return;
}

#define ROUND_LOW_MID_LNORM(RLO, RHI)                            \
   {                                                             \
      m256i carry = m256_srai_i64((RLO), DIGIT_SIZE_52);         \
      carry       = m256_permutexvar_i8(idx8_shuffle, carry);    \
      (RLO)       = m256_and_i64((RLO), filt_rad52);             \
      (RLO)       = m256_mask_add_i64((RLO), 0xE, (RLO), carry); \
      (RHI)       = m256_mask_add_i64((RHI), 0x1, (RHI), carry); \
   }

#define ROUND_HI_LNORM(R)                                     \
   {                                                          \
      m256i carry = m256_srai_i64((R), DIGIT_SIZE_52);        \
      carry       = m256_permutexvar_i8(idx8_shuffle, carry); \
      (R)         = m256_and_i64((R), filt_rad52);            \
      (R)         = m256_mask_add_i64((R), 0xE, (R), carry);  \
   }

#define CREATE_MASK_ONE(OUT, R, MASK_CMP)                                                  \
   {                                                                                       \
      const int mk_lo  = (int)(m256_cmp_i64_mask(filt_rad52, FE521_LO((R)), (MASK_CMP)));  \
      const int mk_mid = (int)(m256_cmp_i64_mask(filt_rad52, FE521_MID((R)), (MASK_CMP))); \
      const int mk_hi  = (int)(m256_cmp_i64_mask(filt_rad52, FE521_HI((R)), (MASK_CMP)));  \
                                                                                           \
      (OUT) = (mk_lo & 0xF) | ((mk_mid & 0xF) << 4) | ((mk_hi & 0xF) << 8);                \
   }

#define ADD_VALUE_BY_MASK(R, MASK, VAL)                                                                        \
   {                                                                                                           \
      FE521_LO((R))  = m256_mask_add_i64(FE521_LO((R)), (mask8)((MASK)&0xF), FE521_LO((R)), (VAL));            \
      FE521_MID((R)) = m256_mask_add_i64(FE521_MID((R)), (mask8)(((MASK) >> 4) & 0xF), FE521_MID((R)), (VAL)); \
      FE521_HI((R))  = m256_mask_add_i64(FE521_HI((R)), (mask8)(((MASK) >> 8) & 0x7), FE521_HI((R)), (VAL));   \
   }

#define FILT_52(R)                                               \
   {                                                             \
      FE521_LO((R))  = m256_and_i64(FE521_LO((R)), filt_rad52);  \
      FE521_MID((R)) = m256_and_i64(FE521_MID((R)), filt_rad52); \
      FE521_HI((R))  = m256_and_i64(FE521_HI((R)), filt_rad52);  \
   }

IPP_OWN_DEFN(void, ifma_lnorm52_p521, (fe521 pr[], const fe521 a))
{
   const m256i filt_rad52   = m256_set1_i64(DIGIT_MASK_52);
   const m256i one          = m256_set1_i64(1ULL);
   const m256i idx8_shuffle = m256_set_i8(23, 22, 21, 20, 19, 18, 17, 16,
                                          15, 14, 13, 12, 11, 10, 9, 8,
                                          7, 6, 5, 4, 3, 2, 1, 0,
                                          31, 30, 29, 28, 27, 26, 25, 24);

   fe521 r;
   FE521_COPY(r, a);

   /* standard step - first round normalization */
   /* low */
   ROUND_LOW_MID_LNORM(FE521_LO(r), FE521_MID(r))
   /* mid */
   ROUND_LOW_MID_LNORM(FE521_MID(r), FE521_HI(r))
   /* hi */
   ROUND_HI_LNORM(FE521_HI(r))

   /* create mask add ONE(1) to slot */
   int k1, k2;
   /* create k2 (r) == 0xF(13) */
   CREATE_MASK_ONE(k2, r, _MM_CMPINT_EQ)
   /* create k1 (r) > 0xF(13) */
   CREATE_MASK_ONE(k1, r, _MM_CMPINT_LT)

   k1 = k2 + (k1 << 1);
   k1 ^= k2;

   ADD_VALUE_BY_MASK(r, k1, one)
   FILT_52(r)

   FE521_COPY(*pr, r);
   return;
}

IPP_OWN_DEFN(void, ifma_lnorm52_dual_p521, (fe521 pr1[], const fe521 a1, fe521 pr2[], const fe521 a2))
{
   const m256i filt_rad52   = m256_set1_i64(DIGIT_MASK_52);
   const m256i one          = m256_set1_i64(1ULL);
   const m256i idx8_shuffle = m256_set_i8(23, 22, 21, 20, 19, 18, 17, 16,
                                          15, 14, 13, 12, 11, 10, 9, 8,
                                          7, 6, 5, 4, 3, 2, 1, 0,
                                          31, 30, 29, 28, 27, 26, 25, 24);
   fe521 r1, r2;
   FE521_COPY(r1, a1);
   FE521_COPY(r2, a2);

   /* standard step - first round normalization */
   /* low */
   ROUND_LOW_MID_LNORM(FE521_LO(r1), FE521_MID(r1))
   ROUND_LOW_MID_LNORM(FE521_LO(r2), FE521_MID(r2))
   /* mid */
   ROUND_LOW_MID_LNORM(FE521_MID(r1), FE521_HI(r1))
   ROUND_LOW_MID_LNORM(FE521_MID(r2), FE521_HI(r2))
   /* hi */
   ROUND_HI_LNORM(FE521_HI(r1))
   ROUND_HI_LNORM(FE521_HI(r2))

   /* create mask add ONE(1) to slot */
   int k11, k21;
   int k12, k22;
   /* create k2 (r) == 0xF(13) */
   CREATE_MASK_ONE(k21, r1, _MM_CMPINT_EQ)
   CREATE_MASK_ONE(k22, r2, _MM_CMPINT_EQ)
   /* create k1 (r) > 0xF(13) */
   CREATE_MASK_ONE(k11, r1, _MM_CMPINT_LT)
   CREATE_MASK_ONE(k12, r2, _MM_CMPINT_LT)

   k11 = k21 + (k11 << 1);
   k11 ^= k21;

   k12 = k22 + (k12 << 1);
   k12 ^= k22;

   ADD_VALUE_BY_MASK(r1, k11, one)
   ADD_VALUE_BY_MASK(r2, k12, one)

   FILT_52(r1)
   FILT_52(r2)

   FE521_COPY(*pr1, r1);
   FE521_COPY(*pr2, r2);
   return;
}

#define group_madd52hi_i64(R, A, B, C)                                \
   FE521_LO(R)  = m256_madd52hi_i64(FE521_LO(A), FE521_LO(B), (C));   \
   FE521_MID(R) = m256_madd52hi_i64(FE521_MID(A), FE521_MID(B), (C)); \
   FE521_HI(R)  = m256_madd52hi_i64(FE521_HI(A), FE521_HI(B), (C))

#define group_madd52lo_i64(R, A, B, C)                                \
   FE521_LO(R)  = m256_madd52lo_i64(FE521_LO(A), FE521_LO(B), (C));   \
   FE521_MID(R) = m256_madd52lo_i64(FE521_MID(A), FE521_MID(B), (C)); \
   FE521_HI(R)  = m256_madd52lo_i64(FE521_HI(A), FE521_HI(B), (C))

#define MUL_ROUND(R, A, BI, BJ)             \
   FE521_SET((R)) = m256_setzero_i64();     \
   group_madd52hi_i64((R), (R), (A), (BI)); \
   group_madd52lo_i64((R), (R), (A), (BJ));

#define REDUCTION(R, U, REDUCT)                                                \
   (U) = m256_permutexvar_i8(idx0, FE521_LO(R));                               \
   /* shift */                                                                 \
   FE521_LO(R)  = m256_alignr_i64(FE521_MID(R), FE521_LO(R), 1);               \
   FE521_MID(R) = m256_alignr_i64(FE521_HI(R), FE521_MID(R), 1);               \
   FE521_HI(R)  = m256_maskz_permutexvar_i8(mask_sr64, idx_sr64, FE521_HI(R)); \
   /* carry chunk 1 */                                                         \
   FE521_LO(REDUCT) = m256_maskz_srai_i64(0x1, (U), DIGIT_SIZE_52);            \
   /* carry chunk 2 */                                                         \
   (U)              = m256_and_i64((U), filt_rad52);                           \
   FE521_HI(REDUCT) = m256_maskz_add_i64(0x2, (U), (U));                       \
   FE521_LO(R)      = m256_add_i64(FE521_LO(R), FE521_LO(REDUCT));             \
   FE521_HI(R)      = m256_add_i64(FE521_HI(R), FE521_HI(REDUCT));

IPP_OWN_DEFN(void, ifma_amm52_p521, (fe521 pr[], const fe521 a, const fe521 b))
{
   const Ipp64s *pb_lo  = (const Ipp64s *)(&(FE521_LO(b)));
   const Ipp64s *pb_mid = (const Ipp64s *)(&(FE521_MID(b)));
   const Ipp64s *pb_hi  = (const Ipp64s *)(&(FE521_HI(b)));

   const m256i b0  = m256_set1_i64(pb_lo[0]);
   const m256i b1  = m256_set1_i64(pb_lo[1]);
   const m256i b2  = m256_set1_i64(pb_lo[2]);
   const m256i b3  = m256_set1_i64(pb_lo[3]);
   const m256i b4  = m256_set1_i64(pb_mid[0]);
   const m256i b5  = m256_set1_i64(pb_mid[1]);
   const m256i b6  = m256_set1_i64(pb_mid[2]);
   const m256i b7  = m256_set1_i64(pb_mid[3]);
   const m256i b8  = m256_set1_i64(pb_hi[0]);
   const m256i b9  = m256_set1_i64(pb_hi[1]);
   const m256i b10 = m256_set1_i64(pb_hi[2]);

   fe521 r0;
   fe521 p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10;

   /* first */
   FE521_SET(r0) = m256_setzero_i64();
   group_madd52lo_i64(r0, r0, a, b0);
   /* last */
   FE521_SET(p10) = m256_setzero_i64();
   group_madd52hi_i64(p10, p10, a, b10);
   /* round mul */
   MUL_ROUND(p0, a, b0, b1)
   MUL_ROUND(p1, a, b1, b2)
   MUL_ROUND(p2, a, b2, b3)
   MUL_ROUND(p3, a, b3, b4)
   MUL_ROUND(p4, a, b4, b5)
   MUL_ROUND(p5, a, b5, b6)
   MUL_ROUND(p6, a, b6, b7)
   MUL_ROUND(p7, a, b7, b8)
   MUL_ROUND(p8, a, b8, b9)
   MUL_ROUND(p9, a, b9, b10)

   const m256i filt_rad52 = m256_set1_i64(DIGIT_MASK_52);
   const m256i idx0       = m256_set_i8(REPL4(7, 6, 5, 4, 3, 2, 1, 0)); /* B[ 0] -> chunk1[0] */
   /* chunk2 shift bit >> 64 */
   const mask32 mask_sr64 = 0x00FFFFFF;
   const m256i idx_sr64   = m256_set_i8(0, 0, 0, 0, 0, 0, 0, 0,
                                      31, 30, 29, 28, 27, 26, 25, 24,
                                      23, 22, 21, 20, 19, 18, 17, 16,
                                      15, 14, 13, 12, 11, 10, 9, 8);

   fe521 reduct;
   FE521_SET(reduct) = m256_setzero_i64();
   m256i u;
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p0);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p1);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p2);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p3);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p4);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p5);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p6);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p7);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p8);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p9);
   REDUCTION(r0, u, reduct)

   fe521_add_no_red(r0, r0, p10);

   FE521_COPY(*pr, r0);
   return;
}

#define MUL_LO_ROUND(R, A,                                                                    \
                     AI, MMI, MAI,                                                            \
                     AJ, MMJ, MAJ)                                                            \
   {                                                                                          \
      fe521 tmp;                                                                              \
      FE521_SET(R) = FE521_SET(tmp) = m256_setzero_i64();                                     \
      /* high */                                                                              \
      FE521_LO(R)  = m256_maskz_madd52hi_i64((MMI), FE521_LO(R), FE521_LO(A), (AI));          \
      FE521_MID(R) = m256_madd52hi_i64(FE521_MID(R), FE521_MID(A), (AI));                     \
      FE521_HI(R)  = m256_madd52hi_i64(FE521_HI(R), FE521_HI(A), (AI));                       \
      /* lo */                                                                                \
      FE521_LO(tmp)  = m256_maskz_madd52lo_i64((MMJ), FE521_LO(tmp), FE521_LO(A), (AJ));      \
      FE521_MID(tmp) = m256_madd52lo_i64(FE521_MID(tmp), FE521_MID(A), (AJ));                 \
      FE521_HI(tmp)  = m256_madd52lo_i64(FE521_HI(tmp), FE521_HI(A), (AJ));                   \
      /* double hi */                                                                         \
      FE521_LO(R)  = m256_mask_add_i64(FE521_LO(R), (MAI), FE521_LO(R), FE521_LO(R));         \
      FE521_MID(R) = m256_add_i64(FE521_MID(R), FE521_MID(R));                                \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(R));                                  \
      /* double lo */                                                                         \
      FE521_LO(tmp)  = m256_mask_add_i64(FE521_LO(tmp), (MAJ), FE521_LO(tmp), FE521_LO(tmp)); \
      FE521_MID(tmp) = m256_add_i64(FE521_MID(tmp), FE521_MID(tmp));                          \
      FE521_HI(tmp)  = m256_add_i64(FE521_HI(tmp), FE521_HI(tmp));                            \
      /* add lo + hi */                                                                       \
      FE521_LO(R)  = m256_add_i64(FE521_LO(R), FE521_LO(tmp));                                \
      FE521_MID(R) = m256_add_i64(FE521_MID(R), FE521_MID(tmp));                              \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(tmp));                                \
   }

#define MUL_LO_LAST_ROUND(R, A,                                                          \
                          AI, MMI, MAI,                                                  \
                          AJ, MMJ)                                                       \
   {                                                                                     \
      fe521 tmp;                                                                         \
      FE521_SET(R) = FE521_SET(tmp) = m256_setzero_i64();                                \
      /* high */                                                                         \
      FE521_LO(R)  = m256_maskz_madd52hi_i64((MMI), FE521_LO(R), FE521_LO(A), (AI));     \
      FE521_MID(R) = m256_madd52hi_i64(FE521_MID(R), FE521_MID(A), (AI));                \
      FE521_HI(R)  = m256_madd52hi_i64(FE521_HI(R), FE521_HI(A), (AI));                  \
      /* lo */                                                                           \
      FE521_LO(tmp)  = m256_maskz_madd52lo_i64((MMJ), FE521_LO(tmp), FE521_LO(A), (AJ)); \
      FE521_MID(tmp) = m256_madd52lo_i64(FE521_MID(tmp), FE521_MID(A), (AJ));            \
      FE521_HI(tmp)  = m256_madd52lo_i64(FE521_HI(tmp), FE521_HI(A), (AJ));              \
      /* double hi */                                                                    \
      FE521_LO(R)  = m256_mask_add_i64(FE521_LO(R), (MAI), FE521_LO(R), FE521_LO(R));    \
      FE521_MID(R) = m256_add_i64(FE521_MID(R), FE521_MID(R));                           \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(R));                             \
      /* double lo */                                                                    \
      FE521_MID(tmp) = m256_add_i64(FE521_MID(tmp), FE521_MID(tmp));                     \
      FE521_HI(tmp)  = m256_add_i64(FE521_HI(tmp), FE521_HI(tmp));                       \
      /* add lo + hi */                                                                  \
      FE521_LO(R)  = m256_add_i64(FE521_LO(R), FE521_LO(tmp));                           \
      FE521_MID(R) = m256_add_i64(FE521_MID(R), FE521_MID(tmp));                         \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(tmp));                           \
   }

#define MUL_MID_FIRST_ROUND(R, A,                                                                \
                            AI, MMI,                                                             \
                            AJ, MAJ)                                                             \
   {                                                                                             \
      fe521 tmp;                                                                                 \
      FE521_SET(R) = FE521_MID(tmp) = FE521_HI(tmp) = m256_setzero_i64();                        \
      /* high */                                                                                 \
      FE521_LO(R)  = m256_maskz_madd52hi_i64((MMI), FE521_LO(R), FE521_LO(A), (AI));             \
      FE521_MID(R) = m256_madd52hi_i64(FE521_MID(R), FE521_MID(A), (AI));                        \
      FE521_HI(R)  = m256_madd52hi_i64(FE521_HI(R), FE521_HI(A), (AI));                          \
      /* lo */                                                                                   \
      FE521_MID(tmp) = m256_madd52lo_i64(FE521_MID(tmp), FE521_MID(A), (AJ));                    \
      FE521_HI(tmp)  = m256_madd52lo_i64(FE521_HI(tmp), FE521_HI(A), (AJ));                      \
      /* double hi */                                                                            \
      FE521_MID(R) = m256_add_i64(FE521_MID(R), FE521_MID(R));                                   \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(R));                                     \
      /* double lo */                                                                            \
      FE521_MID(tmp) = m256_mask_add_i64(FE521_MID(tmp), (MAJ), FE521_MID(tmp), FE521_MID(tmp)); \
      FE521_HI(tmp)  = m256_add_i64(FE521_HI(tmp), FE521_HI(tmp));                               \
      /* add lo + hi */                                                                          \
      FE521_MID(R) = m256_add_i64(FE521_MID(R), FE521_MID(tmp));                                 \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(tmp));                                   \
   }

#define MUL_MID_ROUND(R, A,                                                                      \
                      AI, MMI, MAI,                                                              \
                      AJ, MMJ, MAJ)                                                              \
   {                                                                                             \
      fe521 tmp;                                                                                 \
      FE521_MID(R) = FE521_HI(R) = FE521_MID(tmp) = FE521_HI(tmp) = m256_setzero_i64();          \
      /* high */                                                                                 \
      FE521_MID(R) = m256_maskz_madd52hi_i64((MMI), FE521_MID(R), FE521_MID(A), (AI));           \
      FE521_HI(R)  = m256_madd52hi_i64(FE521_HI(R), FE521_HI(A), (AI));                          \
      /* lo */                                                                                   \
      FE521_MID(tmp) = m256_maskz_madd52lo_i64((MMJ), FE521_MID(tmp), FE521_MID(A), (AJ));       \
      FE521_HI(tmp)  = m256_madd52lo_i64(FE521_HI(tmp), FE521_HI(A), (AJ));                      \
      /* double hi */                                                                            \
      FE521_MID(R) = m256_mask_add_i64(FE521_MID(R), (MAI), FE521_MID(R), FE521_MID(R));         \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(R));                                     \
      /* double lo */                                                                            \
      FE521_MID(tmp) = m256_mask_add_i64(FE521_MID(tmp), (MAJ), FE521_MID(tmp), FE521_MID(tmp)); \
      FE521_HI(tmp)  = m256_add_i64(FE521_HI(tmp), FE521_HI(tmp));                               \
      /* add lo + hi */                                                                          \
      FE521_MID(R) = m256_add_i64(FE521_MID(R), FE521_MID(tmp));                                 \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(tmp));                                   \
   }

#define MUL_MID_LAST_ROUND(R, A,                                                           \
                           AI, MMI, MAI,                                                   \
                           AJ, MMJ)                                                        \
   {                                                                                       \
      fe521 tmp;                                                                           \
      FE521_MID(R) = FE521_HI(R) = FE521_MID(tmp) = FE521_HI(tmp) = m256_setzero_i64();    \
      /* high */                                                                           \
      FE521_MID(R) = m256_maskz_madd52hi_i64((MMI), FE521_MID(R), FE521_MID(A), (AI));     \
      FE521_HI(R)  = m256_madd52hi_i64(FE521_HI(R), FE521_HI(A), (AI));                    \
      /* lo */                                                                             \
      FE521_MID(tmp) = m256_maskz_madd52lo_i64((MMJ), FE521_MID(tmp), FE521_MID(A), (AJ)); \
      FE521_HI(tmp)  = m256_madd52lo_i64(FE521_HI(tmp), FE521_HI(A), (AJ));                \
      /* double hi */                                                                      \
      FE521_MID(R) = m256_mask_add_i64(FE521_MID(R), (MAI), FE521_MID(R), FE521_MID(R));   \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(R));                               \
      /* double lo */                                                                      \
      FE521_HI(tmp) = m256_add_i64(FE521_HI(tmp), FE521_HI(tmp));                          \
      /* add lo + hi */                                                                    \
      FE521_MID(R) = m256_add_i64(FE521_MID(R), FE521_MID(tmp));                           \
      FE521_HI(R)  = m256_add_i64(FE521_HI(R), FE521_HI(tmp));                             \
   }

#define MUL_HI_FIRST_ROUND(R, A,                                                             \
                           AI, MMI,                                                          \
                           AJ, MAJ)                                                          \
   {                                                                                         \
      fe521 tmp;                                                                             \
      FE521_MID(R) = FE521_HI(R) = FE521_HI(tmp) = m256_setzero_i64();                       \
      /* high */                                                                             \
      FE521_MID(R) = m256_maskz_madd52hi_i64((MMI), FE521_MID(R), FE521_MID(A), (AI));       \
      FE521_HI(R)  = m256_madd52hi_i64(FE521_HI(R), FE521_HI(A), (AI));                      \
      /* lo */                                                                               \
      FE521_HI(tmp) = m256_madd52lo_i64(FE521_HI(tmp), FE521_HI(A), (AJ));                   \
      /* double hi */                                                                        \
      FE521_HI(R) = m256_add_i64(FE521_HI(R), FE521_HI(R));                                  \
      /* double lo */                                                                        \
      FE521_HI(tmp) = m256_mask_add_i64(FE521_HI(tmp), (MAJ), FE521_HI(tmp), FE521_HI(tmp)); \
      /* add lo + hi */                                                                      \
      FE521_HI(R) = m256_add_i64(FE521_HI(R), FE521_HI(tmp));                                \
   }

#define MUL_HI_ROUND(R, A,                                                                   \
                     AI, MMI, MAI,                                                           \
                     AJ, MMJ, MAJ)                                                           \
   {                                                                                         \
      fe521 tmp;                                                                             \
      FE521_HI(R) = FE521_HI(tmp) = m256_setzero_i64();                                      \
      /* high */                                                                             \
      FE521_HI(R) = m256_maskz_madd52hi_i64((MMI), FE521_HI(R), FE521_HI(A), (AI));          \
      /* lo */                                                                               \
      FE521_HI(tmp) = m256_maskz_madd52lo_i64((MMJ), FE521_HI(tmp), FE521_HI(A), (AJ));      \
      /* double hi */                                                                        \
      FE521_HI(R) = m256_mask_add_i64(FE521_HI(R), (MAI), FE521_HI(R), FE521_HI(R));         \
      /* double lo */                                                                        \
      FE521_HI(tmp) = m256_mask_add_i64(FE521_HI(tmp), (MAJ), FE521_HI(tmp), FE521_HI(tmp)); \
      /* add lo + hi */                                                                      \
      FE521_HI(R) = m256_add_i64(FE521_HI(R), FE521_HI(tmp));                                \
   }

#define ADD_LO(R, A, B)                                     \
   FE521_LO(R)  = m256_add_i64(FE521_LO(A), FE521_LO(B));   \
   FE521_MID(R) = m256_add_i64(FE521_MID(A), FE521_MID(B)); \
   FE521_HI(R)  = m256_add_i64(FE521_HI(A), FE521_HI(B));

#define ADD_MID(R, A, B)                                    \
   FE521_MID(R) = m256_add_i64(FE521_MID(A), FE521_MID(B)); \
   FE521_HI(R)  = m256_add_i64(FE521_HI(A), FE521_HI(B));

#define ADD_HI(R, A, B) \
   FE521_HI(R) = m256_add_i64(FE521_HI(A), FE521_HI(B));

IPP_OWN_DEFN(void, ifma_ams52_p521, (fe521 pr[], const fe521 a))
{
   const Ipp64s *pa_lo  = (const Ipp64s *)(&(FE521_LO(a)));
   const Ipp64s *pa_mid = (const Ipp64s *)(&(FE521_MID(a)));
   const Ipp64s *pa_hi  = (const Ipp64s *)(&(FE521_HI(a)));

   const m256i a0 = m256_set1_i64(pa_lo[0]);
   const m256i a1 = m256_set1_i64(pa_lo[1]);
   const m256i a2 = m256_set1_i64(pa_lo[2]);
   const m256i a3 = m256_set1_i64(pa_lo[3]);

   const m256i a4 = m256_set1_i64(pa_mid[0]);
   const m256i a5 = m256_set1_i64(pa_mid[1]);
   const m256i a6 = m256_set1_i64(pa_mid[2]);
   const m256i a7 = m256_set1_i64(pa_mid[3]);

   const m256i a8  = m256_set1_i64(pa_hi[0]);
   const m256i a9  = m256_set1_i64(pa_hi[1]);
   const m256i a10 = m256_set1_i64(pa_hi[2]);

   fe521 r0, p0, p1, p2, p3, p4, p5, p6, p7, p8, p9;

   /* start round */
   /* r0 = r0 + a*a[0](lo) */
   FE521_SET(r0) = m256_setzero_i64();
   FE521_LO(r0)  = m256_madd52lo_i64(FE521_LO(r0), FE521_LO(a), a0);
   FE521_MID(r0) = m256_madd52lo_i64(FE521_MID(r0), FE521_MID(a), a0);
   FE521_HI(r0)  = m256_madd52lo_i64(FE521_HI(r0), FE521_HI(a), a0);
   /* r0 = r0 + r0 (no update r0[0]) */
   FE521_LO(r0)  = m256_mask_add_i64(FE521_LO(r0), 0xE, FE521_LO(r0), FE521_LO(r0));
   FE521_MID(r0) = m256_add_i64(FE521_MID(r0), FE521_MID(r0));
   FE521_HI(r0)  = m256_add_i64(FE521_HI(r0), FE521_HI(r0));
   /*
     * 1111 = 0xF
     * 1110 = 0xE
     * 1100 = 0xC
     * 1000 = 0x8
     * 0000 = 0x0
     */
   /* lower */
   /* p0 = p0 + a*a[0](hi) + a*a[1](lo) */
   MUL_LO_ROUND(/* R = */ p0, /* A = */ a,
                /* AI = */ a0, /* MMI = */ 0xF, /* MAI = */ 0xE,
                /* AJ = */ a1, /* MMJ = */ 0xE, /* MAJ = */ 0xC)
   /* p1 = p1 + a*a[1](hi) + a*a[2](lo) */
   MUL_LO_ROUND(/* R = */ p1, /* A = */ a,
                /* AI = */ a1, /* MMI = */ 0xE, /* MAI = */ 0xC,
                /* AJ = */ a2, /* MMJ = */ 0xC, /* MAJ = */ 0x8)
   /* p2 = p2 + a*a[2](hi) + a*a[3](lo) */
   MUL_LO_LAST_ROUND(/* R = */ p2, /* A = */ a,
                     /* AI = */ a2, /* MMI = */ 0xC, /* MAI = */ 0x8,
                     /* AJ = */ a3, /* MMJ = */ 0x8)
   /* mid */
   /* p3 = p3 + a*a[3](hi) + a*a[4](lo) */
   MUL_MID_FIRST_ROUND(/* R = */ p3, /* A = */ a,
                       /* AI = */ a3, /* MMI = */ 0x8,
                       /* AJ = */ a4, /* MAJ = */ 0xE)
   /* p4 = p4 + a*a[4](hi) + a*a[5](lo) */
   MUL_MID_ROUND(/* R = */ p4, /* A = */ a,
                 /* AI = */ a4, /* MMI = */ 0xF, /* MAI = */ 0xE,
                 /* AJ = */ a5, /* MMJ = */ 0xE, /* MAJ = */ 0xC)
   /* p5 = p5 + a*a[5](hi) + a*a[6](lo) */
   MUL_MID_ROUND(/* R = */ p5, /* A = */ a,
                 /* AI = */ a5, /* MMI = */ 0xE, /* MAI = */ 0xC,
                 /* AJ = */ a6, /* MMJ = */ 0xC, /* MAJ = */ 0x8)
   /* p6 = p6 + a*a[6](hi) + a*a[7](lo) */
   MUL_MID_LAST_ROUND(/* R = */ p6, /* A = */ a,
                      /* AI = */ a6, /* MMI = */ 0xC, /* MAI = */ 0x8,
                      /* AJ = */ a7, /* MMJ = */ 0x8)
   /* high */
   /* p7 = p7 + a*a[7](hi) + a*a[8](lo) */
   MUL_HI_FIRST_ROUND(/* R = */ p7, /* A = */ a,
                      /* AI = */ a7, /* MMI = */ 0x8,
                      /* AJ = */ a8, /* MAJ = */ 0xE)
   /* p8 = p8 + a*a[8](hi) + a*a[9](lo) */
   MUL_HI_ROUND(/* R = */ p8, /* A = */ a,
                /* AI = */ a8, /* MMI = */ 0xF, /* MAI = */ 0xE,
                /* AJ = */ a9, /* MMJ = */ 0xE, /* MAJ = */ 0xC)
   /* p9 = p9 + a*a[9](hi) + a*a[10](lo) */
   MUL_HI_ROUND(/* R = */ p9, /* A = */ a,
                /* AI = */ a9, /* MMI = */ 0xE, /* MAI = */ 0xC,
                /* AJ = */ a10, /* MMJ = */ 0xC, /* MAJ = */ 0x8)

   fe521 reduct;
   FE521_SET(reduct) = m256_setzero_i64();
   m256i u;
   const m256i filt_rad52 = m256_set1_i64(DIGIT_MASK_52);
   const m256i idx0       = m256_set_i8(REPL4(7, 6, 5, 4, 3, 2, 1, 0)); /* B[ 0] -> chunk1[0] */
   /* chunk2 shift bit >> 64 */
   const mask32 mask_sr64 = 0x00FFFFFF;
   const m256i idx_sr64   = m256_set_i8(0, 0, 0, 0, 0, 0, 0, 0,
                                      31, 30, 29, 28, 27, 26, 25, 24,
                                      23, 22, 21, 20, 19, 18, 17, 16,
                                      15, 14, 13, 12, 11, 10, 9, 8);
   REDUCTION(r0, u, reduct)

   ADD_LO(r0, r0, p0);
   REDUCTION(r0, u, reduct)

   ADD_LO(r0, r0, p1);
   REDUCTION(r0, u, reduct)

   ADD_LO(r0, r0, p2);
   REDUCTION(r0, u, reduct)

   ADD_LO(r0, r0, p3);
   REDUCTION(r0, u, reduct)

   ADD_MID(r0, r0, p4);
   REDUCTION(r0, u, reduct)

   ADD_MID(r0, r0, p5);
   REDUCTION(r0, u, reduct)

   ADD_MID(r0, r0, p6);
   REDUCTION(r0, u, reduct)

   ADD_MID(r0, r0, p7);
   REDUCTION(r0, u, reduct)

   ADD_HI(r0, r0, p8);
   REDUCTION(r0, u, reduct)

   ADD_HI(r0, r0, p9);
   REDUCTION(r0, u, reduct)

   FE521_COPY(*pr, r0);
   return;
}

IPP_OWN_DEFN(void, ifma_ams52_dual_p521, (fe521 pr1[], const fe521 a1, fe521 pr2[], const fe521 a2))
{
   ifma_amm52_dual_p521(pr1, a1, a1, pr2, a2, a2);
}

IPP_OWN_DEFN(void, ifma_amm52_dual_p521,
             (fe521 pr1[], const fe521 a1, const fe521 b1,
              fe521 pr2[], const fe521 a2, const fe521 b2))
{
   const Ipp64s *pb_lo_1  = (const Ipp64s *)(&(FE521_LO(b1)));
   const Ipp64s *pb_mid_1 = (const Ipp64s *)(&(FE521_MID(b1)));
   const Ipp64s *pb_hi_1  = (const Ipp64s *)(&(FE521_HI(b1)));
   const Ipp64s *pb_lo_2  = (const Ipp64s *)(&(FE521_LO(b2)));
   const Ipp64s *pb_mid_2 = (const Ipp64s *)(&(FE521_MID(b2)));
   const Ipp64s *pb_hi_2  = (const Ipp64s *)(&(FE521_HI(b2)));

   const m256i b0_1  = m256_set1_i64(pb_lo_1[0]);
   const m256i b1_1  = m256_set1_i64(pb_lo_1[1]);
   const m256i b2_1  = m256_set1_i64(pb_lo_1[2]);
   const m256i b3_1  = m256_set1_i64(pb_lo_1[3]);
   const m256i b4_1  = m256_set1_i64(pb_mid_1[0]);
   const m256i b5_1  = m256_set1_i64(pb_mid_1[1]);
   const m256i b6_1  = m256_set1_i64(pb_mid_1[2]);
   const m256i b7_1  = m256_set1_i64(pb_mid_1[3]);
   const m256i b8_1  = m256_set1_i64(pb_hi_1[0]);
   const m256i b9_1  = m256_set1_i64(pb_hi_1[1]);
   const m256i b10_1 = m256_set1_i64(pb_hi_1[2]);

   const m256i b0_2  = m256_set1_i64(pb_lo_2[0]);
   const m256i b1_2  = m256_set1_i64(pb_lo_2[1]);
   const m256i b2_2  = m256_set1_i64(pb_lo_2[2]);
   const m256i b3_2  = m256_set1_i64(pb_lo_2[3]);
   const m256i b4_2  = m256_set1_i64(pb_mid_2[0]);
   const m256i b5_2  = m256_set1_i64(pb_mid_2[1]);
   const m256i b6_2  = m256_set1_i64(pb_mid_2[2]);
   const m256i b7_2  = m256_set1_i64(pb_mid_2[3]);
   const m256i b8_2  = m256_set1_i64(pb_hi_2[0]);
   const m256i b9_2  = m256_set1_i64(pb_hi_2[1]);
   const m256i b10_2 = m256_set1_i64(pb_hi_2[2]);

   fe521 r0_1;
   fe521 p0_1, p1_1, p2_1, p3_1, p4_1, p5_1, p6_1, p7_1, p8_1, p9_1, p10_1;
   fe521 r0_2;
   fe521 p0_2, p1_2, p2_2, p3_2, p4_2, p5_2, p6_2, p7_2, p8_2, p9_2, p10_2;

   /* first */
   FE521_SET(r0_1) = m256_setzero_i64();
   group_madd52lo_i64(r0_1, r0_1, a1, b0_1);
   FE521_SET(r0_2) = m256_setzero_i64();
   group_madd52lo_i64(r0_2, r0_2, a2, b0_2);
   /* last */
   FE521_SET(p10_1) = m256_setzero_i64();
   group_madd52hi_i64(p10_1, p10_1, a1, b10_1);
   FE521_SET(p10_2) = m256_setzero_i64();
   group_madd52hi_i64(p10_2, p10_2, a2, b10_2);
   /* round mul */
   MUL_ROUND(p0_1, a1, b0_1, b1_1)
   MUL_ROUND(p0_2, a2, b0_2, b1_2)

   MUL_ROUND(p1_1, a1, b1_1, b2_1)
   MUL_ROUND(p1_2, a2, b1_2, b2_2)

   MUL_ROUND(p2_1, a1, b2_1, b3_1)
   MUL_ROUND(p2_2, a2, b2_2, b3_2)

   MUL_ROUND(p3_1, a1, b3_1, b4_1)
   MUL_ROUND(p3_2, a2, b3_2, b4_2)

   MUL_ROUND(p4_1, a1, b4_1, b5_1)
   MUL_ROUND(p4_2, a2, b4_2, b5_2)

   MUL_ROUND(p5_1, a1, b5_1, b6_1)
   MUL_ROUND(p5_2, a2, b5_2, b6_2)

   MUL_ROUND(p6_1, a1, b6_1, b7_1)
   MUL_ROUND(p6_2, a2, b6_2, b7_2)

   MUL_ROUND(p7_1, a1, b7_1, b8_1)
   MUL_ROUND(p7_2, a2, b7_2, b8_2)

   MUL_ROUND(p8_1, a1, b8_1, b9_1)
   MUL_ROUND(p8_2, a2, b8_2, b9_2)

   MUL_ROUND(p9_1, a1, b9_1, b10_1)
   MUL_ROUND(p9_2, a2, b9_2, b10_2)

   const m256i filt_rad52 = m256_set1_i64(DIGIT_MASK_52);
   const m256i idx0       = m256_set_i8(REPL4(7, 6, 5, 4, 3, 2, 1, 0)); /* B[ 0] -> chunk1[0] */
   /* chunk2 shift bit >> 64 */
   const mask32 mask_sr64 = 0x00FFFFFF;
   const m256i idx_sr64   = m256_set_i8(0, 0, 0, 0, 0, 0, 0, 0,
                                      31, 30, 29, 28, 27, 26, 25, 24,
                                      23, 22, 21, 20, 19, 18, 17, 16,
                                      15, 14, 13, 12, 11, 10, 9, 8);

   fe521 reduct_1;
   FE521_SET(reduct_1) = m256_setzero_i64();
   m256i u_1;
   fe521 reduct_2;
   FE521_SET(reduct_2) = m256_setzero_i64();
   m256i u_2;
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p0_1);
   fe521_add_no_red(r0_2, r0_2, p0_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p1_1);
   fe521_add_no_red(r0_2, r0_2, p1_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p2_1);
   fe521_add_no_red(r0_2, r0_2, p2_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p3_1);
   fe521_add_no_red(r0_2, r0_2, p3_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p4_1);
   fe521_add_no_red(r0_2, r0_2, p4_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p5_1);
   fe521_add_no_red(r0_2, r0_2, p5_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p6_1);
   fe521_add_no_red(r0_2, r0_2, p6_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p7_1);
   fe521_add_no_red(r0_2, r0_2, p7_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p8_1);
   fe521_add_no_red(r0_2, r0_2, p8_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p9_1);
   fe521_add_no_red(r0_2, r0_2, p9_2);
   REDUCTION(r0_1, u_1, reduct_1)
   REDUCTION(r0_2, u_2, reduct_2)

   fe521_add_no_red(r0_1, r0_1, p10_1);
   fe521_add_no_red(r0_2, r0_2, p10_2);

   FE521_COPY(*pr1, r0_1);
   FE521_COPY(*pr2, r0_2);
   return;
}

#undef group_madd52hi_i64
#undef group_madd52lo_i64

IPP_OWN_DEFN(void, ifma_half52_p521, (fe521 pr[], const fe521 a))
{
   fe521 M;
   FE521_LOADU(M, p521_x1);
   const m256i zero = m256_setzero_i64();
   const m256i one  = m256_set1_i64(1LL);

   const mask8 mask_last_bit_one_line = m256_cmp_i64_mask(m256_and_i64(FE521_LO(a), one), zero, _MM_CMPINT_EQ);
   const mask8 mask_is_lb_one         = (mask8)((mask_last_bit_one_line & 1) - 1);

   fe521 r;
   FE521_LO(r)  = _mm256_mask_add_epi64(FE521_LO(a), mask_is_lb_one, FE521_LO(a), FE521_LO(M));
   FE521_MID(r) = _mm256_mask_add_epi64(FE521_MID(a), mask_is_lb_one, FE521_MID(a), FE521_MID(M));
   FE521_HI(r)  = _mm256_mask_add_epi64(FE521_HI(a), mask_is_lb_one, FE521_HI(a), FE521_HI(M));
   ifma_lnorm52_p521(&r, r);

   /* 1-bit shift right */
   /* chunk2 shift bit >> 64 */
   const mask32 mask_sr64 = 0xFFFF;
   const m256i idx_sr64   = m256_set_i8(24, 24, 24, 24, 24, 24, 24, 24,
                                      24, 24, 24, 24, 24, 24, 24, 24,
                                      23, 22, 21, 20, 19, 18, 17, 16,
                                      15, 14, 13, 12, 11, 10, 9, 8);

   fe521 shift_right;
   /* shift right */
   FE521_LO(shift_right)  = m256_alignr_i64(FE521_MID(r), FE521_LO(r), 1);
   FE521_MID(shift_right) = m256_alignr_i64(FE521_HI(r), FE521_MID(r), 1);
   FE521_HI(shift_right)  = m256_maskz_permutexvar_i8(mask_sr64, idx_sr64, FE521_HI(r));
   /* extract las bit */
   FE521_LO(shift_right)  = m256_and_i64(FE521_LO(shift_right), one);
   FE521_MID(shift_right) = m256_and_i64(FE521_MID(shift_right), one);
   FE521_HI(shift_right)  = m256_and_i64(FE521_HI(shift_right), one);
   /* set last bit is first byte (52 radix) */
   FE521_LO(shift_right)  = m256_slli_i64(FE521_LO(shift_right), DIGIT_SIZE_52 - 1);
   FE521_MID(shift_right) = m256_slli_i64(FE521_MID(shift_right), DIGIT_SIZE_52 - 1);
   FE521_HI(shift_right)  = m256_maskz_slli_i64(0x3, FE521_HI(shift_right), DIGIT_SIZE_52 - 1);
   /* join first new bite */
   FE521_LO(r)  = m256_srli_i64(FE521_LO(r), 1);
   FE521_MID(r) = m256_srli_i64(FE521_MID(r), 1);
   FE521_HI(r)  = m256_maskz_srli_i64(0x7, FE521_HI(r), 1);
   /* join first and other bit */
   FE521_LO(r)  = m256_add_i64(FE521_LO(r), FE521_LO(shift_right));
   FE521_MID(r) = m256_add_i64(FE521_MID(r), FE521_MID(shift_right));
   FE521_HI(r)  = m256_add_i64(FE521_HI(r), FE521_HI(shift_right));

   FE521_COPY(*pr, r);
   return;
}

IPP_OWN_DEFN(void, ifma_neg52_p521, (fe521 pr[], const fe521 a))
{
   fe521 M4;
   FE521_LOADU(M4, p521_x4);

   const mask8 mask_is_not_zero = (mask8)(~(FE521_IS_ZERO(a)));
   fe521 r;
   FE521_LO(r)  = m256_mask_sub_i64(FE521_LO(a), mask_is_not_zero, FE521_LO(M4), FE521_LO(a));
   FE521_MID(r) = m256_mask_sub_i64(FE521_MID(a), mask_is_not_zero, FE521_MID(M4), FE521_MID(a));
   FE521_HI(r)  = m256_mask_sub_i64(FE521_HI(a), mask_is_not_zero, FE521_HI(M4), FE521_HI(a));
   ifma_norm52_p521(&r, r);

   FE521_COPY(*pr, r);
   return;
}

/* to Montgomery conversion constant
 * rr = 2^((P521_LEN52*DIGIT_SIZE)*2) mod p521
 */
static const __ALIGN64 Ipp64u P521R1_RR52[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = { { 0x0000000000000000,
                                                                                      0x0004000000000000,
                                                                                      0x0000000000000000,
                                                                                      0x0000000000000000 },
                                                                                    { 0x0000000000000000,
                                                                                      0x0000000000000000,
                                                                                      0x0000000000000000,
                                                                                      0x0000000000000000 },
                                                                                    { 0x0000000000000000,
                                                                                      0x0000000000000000,
                                                                                      0x0000000000000000,
                                                                                      0x0000000000000000 } };

IPP_OWN_DEFN(void, ifma_tomont52_p521, (fe521 pr[], const fe521 a))
{
   fe521 RR;
   FE521_LOADU(RR, P521R1_RR52);
   ifma_amm52_p521(pr, a, RR);
   ifma_lnorm52_p521(pr, *pr);
   return;
}

static IPP_OWN_DEFN(void, ifma_fastred52_p521, (fe521 pr[], const fe521 a))
{
   fe521 M;
   FE521_LOADU(M, p521_x1);
   const m256i zero = m256_setzero_i64();

   fe521 r;
   fe521_sub_no_red(r, a, M);
   ifma_norm52_p521(&r, r);

   const mask8 lt   = m256_cmp_i64_mask(zero, m256_srli_i64(FE521_HI(r), DIGIT_SIZE_52 - 1), _MM_CMPINT_LT);
   const mask8 mask = (mask8)((mask8)0 - ((lt >> 2) & 1));

   /* mask != 0 ? a : r */
   FE521_MASK_MOV(r, r, mask, a);
   FE521_COPY(*pr, r);
   return;
}

IPP_OWN_DEFN(void, ifma_frommont52_p521, (fe521 pr[], const fe521 a))
{
   fe521 ONE;
   FE521_LOADU(ONE, P521R1_ONE52);
   ifma_amm52_p521(pr, a, ONE);
   ifma_lnorm52_p521(pr, *pr);
   ifma_fastred52_p521(pr, *pr);
   return;
}

__IPPCP_INLINE IPP_OWN_DEFN(void, ifma_amm52_p521_norm, (fe521 pr[], const fe521 a, const fe521 b))
{
   ifma_amm52_p521(pr, a, b);
   ifma_lnorm52_p521(pr, *pr);
   return;
}

__IPPCP_INLINE IPP_OWN_DEFN(void, ifma_ams52_p521_norm, (fe521 pr[], const fe521 a))
{
   ifma_ams52_p521(pr, a);
   ifma_lnorm52_p521(pr, *pr);
   return;
}

#define mul(R, A, B) ifma_amm52_p521_norm(&(R), (A), (B))
#define sqr(R, A) ifma_ams52_p521_norm(&(R), (A))
#define mul_dual(R1, A1, B1, R2, A2, B2)                       \
   ifma_amm52_dual_p521(&(R1), (A1), (B1), &(R2), (A2), (B2)); \
   ifma_lnorm52_dual_p521(&(R1), (R1), &(R2), (R2))

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

IPP_OWN_DEFN(void, ifma_aminv52_p521, (fe521 pr[], const fe521 z))
{
   fe521 u, v, zD, zF, z1FF;
   FE521_SET(u) = FE521_SET(v) = FE521_SET(zD) = FE521_SET(zF) = FE521_SET(z1FF) = m256_setzero_i64();

   sqr(u, z);             /* u = z^2 */
   mul(v, u, z);          /* v = z^2 * z     = z^3  */
   sqr_ntimes(zF, v, 2);  /* zF= (z^3)^(2^2) = z^12 */
                          /**/
   mul_dual(zD, zF, z,    /* zD = z^12 * z    = z^xD */
            zF, zF, v);   /* zF = z^12 * z^3  = z^xF */
                          /**/
   sqr_ntimes(u, zF, 4);  /* u  = (z^xF)^(2^4)  = z^xF0 */
   mul_dual(zD, u, zD,    /* zD = z^xF0 * z^xD  = z^xFD */
            zF, u, zF);   /* zF = z^xF0 * z^xF  = z^xFF */
                          /**/
   sqr(z1FF, zF);         /* z1FF= (zF^2) = z^x1FE */
   mul(z1FF, z1FF, z);    /* z1FF *= z    = z^x1FF */
                          /**/
   sqr_ntimes(u, zF, 8);  /* u = (z^xFF)^(2^8)    = z^xFF00 */
   mul_dual(zD, u, zD,    /* zD = z^xFF00 * z^xFD = z^xFFFD */
            zF, u, zF);   /* zF = z^xFF00 * z^xFF = z^xFFFF */
                          /**/
   sqr_ntimes(u, zF, 16); /* u = (z^xFFFF)^(2^16)       = z^xFFFF0000 */
   mul_dual(zD, u, zD,    /* zD = z^xFFFF0000 * z^xFFFD = z^xFFFFFFFD */
            zF, u, zF);   /* zF = z^xFFFF0000 * z^xFFFF = z^xFFFFFFFF */
                          /**/
   sqr_ntimes(u, zF, 32); /* u = (z^xFFFFFFFF)^(2^32)               = z^xFFFFFFFF00000000 */
   mul_dual(zD, u, zD,    /* zD = z^xFFFFFFFF00000000 * z^xFFFFFFFD = z^xFFFFFFFFFFFFFFFD */
            zF, u, zF);   /* zF = z^xFFFFFFFF00000000 * z^xFFFFFFFF = z^xFFFFFFFFFFFFFFFF */

   /* v = z^x1FF.0000000000000000 * z^xFFFFFFFFFFFFFFFF
         = z^x1FF.FFFFFFFFFFFFFFFF */
   sqr_ntimes(v, z1FF, 64);
   mul(v, v, zF);

   /* v = z^x1FF.FFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFF
         = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF */
   sqr_ntimes(v, v, 64);
   mul(v, v, zF);

   /* v = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFF
         = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF */
   sqr_ntimes(v, v, 64);
   mul(v, v, zF);

   /* v = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFF
         = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF */
   sqr_ntimes(v, v, 64);
   mul(v, v, zF);

   /* v = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFF
         = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFE.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF */
   sqr_ntimes(v, v, 64);
   mul(v, v, zF);

   /* v = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFF
         = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFE.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF */
   sqr_ntimes(v, v, 64);
   mul(v, v, zF);

   /* v = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFF
         = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFE.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF */
   sqr_ntimes(v, v, 64);
   mul(v, v, zF);

   /* v = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.0000000000000000 * z^xFFFFFFFFFFFFFFFD
         = z^x1FF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFE.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFD */
   sqr_ntimes(v, v, 64);
   mul(*pr, v, zD);
   return;
}

#define ROUND_CONV_64_TO_52(R, A, MASK_LOAD, MASK_RAD52, IDX16) \
   (R) = m256_maskz_loadu_i64((MASK_LOAD), (A));                \
   (R) = m256_permutexvar_i16((IDX16), (R));                    \
   (R) = m256_srlv_i64((R), shift_right);                       \
   (R) = m256_and_i64((MASK_RAD52), (R));

IPP_OWN_DEFN(void, convert_radix_to_52_p521, (fe521 pr[], const Ipp64u arad64[P521R1_LEN64]))
{

   /* chunk 1 */
   const m256i idx16c1 = m256_set_i16(12, 11, 10, 9,
                                      9, 8, 7, 6,
                                      6, 5, 4, 3,
                                      3, 2, 1, 0);
   const m256i idx16c2 = m256_set_i16(13, 12, 11, 10,
                                      10, 9, 8, 7,
                                      7, 6, 5, 4,
                                      4, 3, 2, 1);
   const m256i idx16c3 = m256_set_i16(12, 12, 12, 12,
                                      12, 12, 12, 8,
                                      8, 7, 6, 5,
                                      5, 4, 3, 2);

   const m256i shift_right   = m256_set_i64(12LL, 8LL, 4LL, 0LL);
   const m256i mask_rad52c12 = m256_set1_i64(DIGIT_MASK_52);
   const m256i mask_rad52c3  = m256_set_i64(0x0, 0x1, DIGIT_MASK_52, DIGIT_MASK_52);

   fe521 r;
   FE521_SET(r) = m256_setzero_i64();

   /* chunk 1 */
   ROUND_CONV_64_TO_52(FE521_LO(r), arad64, 0xF, mask_rad52c12, idx16c1)
   /* chunk 2 */
   ROUND_CONV_64_TO_52(FE521_MID(r), arad64 + 3, 0xF, mask_rad52c12, idx16c2)
   /* chunk 2 */
   ROUND_CONV_64_TO_52(FE521_HI(r), arad64 + 6, 0x7, mask_rad52c3, idx16c3)

   FE521_COPY(*pr, r);
   return;
}

IPP_OWN_DEFN(void, convert_radix_to_64_p521, (Ipp64u rrad64[P521R1_LEN64], const fe521 a))
{
   /* filter chunk3 */
   const m256i mask_filtc3 = m256_set_i64(0x0, 0x1, DIGIT_MASK_52, DIGIT_MASK_52);
   const m256i shift_left  = m256_set_i64(4LL, 0LL, 4LL, 0LL);
   /* idx create chunk1 */
   const m256i idx8_upc1c1   = m256_set_i8(31, 31, 31, 31, 31, 31, 31, 31,
                                         23, 23, 23, 23, 22, 21, 20, 19,
                                         15, 15, 15, 14, 13, 12, 11, 10,
                                         7, 6, 5, 4, 3, 2, 1, 0);
   const m256i idx8_downc1c1 = m256_set_i8(31, 31, 31, 31, 31, 31, 30, 29,
                                           28, 27, 26, 25, 24, 23, 23, 23,
                                           18, 17, 16, 15, 15, 15, 15, 15,
                                           9, 8, 7, 7, 7, 7, 7, 7);
   const m256i idx8_upc2c1   = m256_set_i8(5, 4, 3, 2, 1, 0, 7, 7,
                                         7, 7, 7, 7, 7, 7, 7, 7,
                                         7, 7, 7, 7, 7, 7, 7, 7,
                                         7, 7, 7, 7, 7, 7, 7, 7);
   /* idx create chunk 2 */
   const m256i idx8_upc2c2   = m256_set_i8(31, 31, 31, 31, 31, 31, 31, 31,
                                         31, 31, 31, 31, 31, 31, 31, 31,
                                         23, 23, 22, 21, 20, 19, 18, 17,
                                         16, 7, 7, 7, 7, 7, 7, 6);
   const m256i idx8_downc2c2 = m256_set_i8(31, 31, 31, 31, 31, 31, 31, 31,
                                           31, 31, 31, 31, 30, 29, 28, 27,
                                           26, 25, 24, 23, 23, 23, 23, 23,
                                           15, 14, 13, 12, 11, 10, 9, 8);
   const m256i idx8_upc3c2   = m256_set_i8(13, 12, 11, 10, 9, 8, 7, 7,
                                         7, 7, 7, 7, 7, 7, 7, 7,
                                         7, 7, 7, 7, 7, 7, 7, 7,
                                         7, 7, 7, 7, 7, 7, 7, 7);
   const m256i idx8_downc3c2 = m256_set_i8(7, 7, 7, 7, 7, 6, 5, 4,
                                           3, 2, 1, 0, 7, 7, 7, 7,
                                           7, 7, 7, 7, 7, 7, 7, 7,
                                           7, 7, 7, 7, 7, 7, 7, 7);
   /* idx create chunk 3 */
   const m256i idx8_upc3c3   = m256_set_i8(15, 15, 15, 15, 15, 15, 15, 15,
                                         15, 15, 15, 15, 15, 15, 15, 15,
                                         15, 15, 15, 15, 15, 15, 15, 15,
                                         15, 15, 15, 15, 15, 15, 16, 15);
   const m256i idx8_downc3c3 = m256_set_i8(15, 15, 15, 15, 15, 15, 15, 15,
                                           15, 15, 15, 15, 15, 15, 15, 15,
                                           15, 15, 15, 15, 15, 15, 15, 15,
                                           15, 15, 15, 15, 15, 15, 15, 14);

   fe521 r;
   /* shift left */
   FE521_LO(r)  = m256_sllv_i64(FE521_LO(a), shift_left);
   FE521_MID(r) = m256_sllv_i64(FE521_MID(a), shift_left);
   FE521_HI(r)  = m256_and_i64(FE521_HI(a), mask_filtc3);
   FE521_HI(r)  = m256_sllv_i64(FE521_HI(r), shift_left);

   m256i t1, t2, t3;
   /* chunk 1 */
   t1 = m256_permutexvar_i8(idx8_upc1c1, FE521_LO(r));
   t2 = m256_permutexvar_i8(idx8_downc1c1, FE521_LO(r));
   t1 = m256_or_i64(t1, t2);
   t3 = m256_permutexvar_i8(idx8_upc2c1, FE521_MID(r));

   FE521_LO(r) = m256_or_i64(t3, t1);

   /* chunk 2 */
   t1 = m256_permutexvar_i8(idx8_upc2c2, FE521_MID(r));
   t2 = m256_permutexvar_i8(idx8_downc2c2, FE521_MID(r));
   t3 = m256_or_i64(t1, t2);
   t1 = m256_permutexvar_i8(idx8_upc3c2, FE521_HI(r));
   t2 = m256_permutexvar_i8(idx8_downc3c2, FE521_HI(r));

   FE521_MID(r) = m256_or_i64(t3, m256_or_i64(t1, t2));

   /* chunk 3 */
   t1 = m256_permutexvar_i8(idx8_upc3c3, FE521_HI(r));
   t2 = m256_permutexvar_i8(idx8_downc3c3, FE521_HI(r));

   FE521_HI(r) = m256_or_i64(t1, t2);

   /* store */
   m256_storeu_i64(rrad64, FE521_LO(r));
   m256_storeu_i64(rrad64 + 4, FE521_MID(r));
   m256_mask_storeu_i64(rrad64 + 8, 0x1, FE521_HI(r));

   return;
}

#endif // (_IPP32E >= _IPP32E_K1)
