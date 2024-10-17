/*************************************************************************
* Copyright (C) 2022 Intel Corporation
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

#include "gfpec/ecnist/ifma_defs.h"
#include "gfpec/ecnist/ifma_norm.h"
#include <stdio.h>

IPP_OWN_DEFN(m512, ifma_lnorm52, (const m512 a))
{
   const m512 mask52             = set1_i64(DIGIT_MASK);
   const m512 one                = set1_i64(1ULL);
   const mask64 mask_shift_carry = 0xffffffffffffff00;

   const m512 idxi8 = set_i64(0x3736353433323130, // 55, 54, 53, 52, 51, 50, 49, 48
                              0x2f2e2d2c2b2a2928, // 47, 46, 45, 44, 43, 42, 41, 40
                              0x2726252423222120, // 39, 38, 37, 36, 35, 34, 33, 32
                              0x1f1e1d1c1b1a1918, // 31, 30, 29, 28, 27, 26, 25, 24
                              0x1716151413121110, // 23, 22, 21, 20, 19, 18, 17, 16
                              0x0f0e0d0c0b0a0908, // 15, 14, 13, 12, 11, 10,  9,  8
                              0x0706050403020100, //  7,  6,  5,  4,  3,  2,  1,  0
                              0x0);             //  0,  0,  0,  0,  0,  0,  0,  0

   m512 r = a;
   int k1, k2;
   m512 carry = srai_i64(r, DIGIT_SIZE);
   carry      = maskz_permutexvar_i8(mask_shift_carry, idxi8, carry);

   r = and_i64(r, mask52);
   r = add_i64(r, carry);

   k2 = (int)(cmp_i64_mask(mask52, r, _MM_CMPINT_EQ));
   k1 = (int)(cmp_i64_mask(mask52, r, _MM_CMPINT_LT));

   k1 = k2 + (k1 << 1);
   k1 ^= k2;

   r = mask_add_i64(r, (mask8)(k1), r, one);
   r = and_i64(r, mask52);

   return r;
}

IPP_OWN_DEFN(void, ifma_lnorm52_dual, (m512 pr1[], const m512 a1, m512 pr2[], const m512 a2))
{
   const m512 mask52             = set1_i64(DIGIT_MASK);
   const m512 one                = set1_i64(1UL);
   const mask64 mask_shift_carry = 0xffffffffffffff00;

   const m512 idxi8 = set_i64(0x3736353433323130, // 55, 54, 53, 52, 51, 50, 49, 48
                              0x2f2e2d2c2b2a2928, // 47, 46, 45, 44, 43, 42, 41, 40
                              0x2726252423222120, // 39, 38, 37, 36, 35, 34, 33, 32
                              0x1f1e1d1c1b1a1918, // 31, 30, 29, 28, 27, 26, 25, 24
                              0x1716151413121110, // 23, 22, 21, 20, 19, 18, 17, 16
                              0x0f0e0d0c0b0a0908, // 15, 14, 13, 12, 11, 10,  9,  8
                              0x0706050403020100, //  7,  6,  5,  4,  3,  2,  1,  0
                              0x0);             //  0,  0,  0,  0,  0,  0,  0,  0

   m512 r1 = a1;
   m512 r2 = a2;
   int k1_1, k1_2, k2_1, k2_2;

   m512 carry1 = srai_i64(r1, DIGIT_SIZE);
   m512 carry2 = srai_i64(r2, DIGIT_SIZE);
   carry1      = maskz_permutexvar_i8(mask_shift_carry, idxi8, carry1);
   carry2      = maskz_permutexvar_i8(mask_shift_carry, idxi8, carry2);

   r1 = and_i64(r1, mask52);
   r1 = add_i64(r1, carry1);
   r2 = and_i64(r2, mask52);
   r2 = add_i64(r2, carry2);

   k2_1 = (int)(cmp_i64_mask(mask52, r1, _MM_CMPINT_EQ));
   k1_1 = (int)(cmp_i64_mask(mask52, r1, _MM_CMPINT_LT));
   k2_2 = (int)(cmp_i64_mask(mask52, r2, _MM_CMPINT_EQ));
   k1_2 = (int)(cmp_i64_mask(mask52, r2, _MM_CMPINT_LT));

   k1_1 = k2_1 + (k1_1 << 1);
   k1_1 ^= k2_1;
   k1_2 = k2_2 + (k1_2 << 1);
   k1_2 ^= k2_2;

   r1 = mask_add_i64(r1, (mask8)(k1_1), r1, one);
   r1 = and_i64(r1, mask52);
   r2 = mask_add_i64(r2, (mask8)(k1_2), r2, one);
   r2 = and_i64(r2, mask52);

   *pr1 = r1;
   *pr2 = r2;
   return;
}


IPP_OWN_DEFN(m512, ifma_norm52, (const m512 a))
{
   const m512 mask52             = set1_i64(DIGIT_MASK);
   const m512 one                = set1_i64(1LL);
   const m512 mone               = set1_i64(-1LL);
   const mask64 mask_shift_carry = 0xFFFFFFFFFFFFFF00;

   const m512 idxi8 = set_i64(0x3736353433323130, // 55, 54, 53, 52, 51, 50, 49, 48
                              0x2f2e2d2c2b2a2928, // 47, 46, 45, 44, 43, 42, 41, 40
                              0x2726252423222120, // 39, 38, 37, 36, 35, 34, 33, 32
                              0x1f1e1d1c1b1a1918, // 31, 30, 29, 28, 27, 26, 25, 24
                              0x1716151413121110, // 23, 22, 21, 20, 19, 18, 17, 16
                              0x0f0e0d0c0b0a0908, // 15, 14, 13, 12, 11, 10,  9,  8
                              0x0706050403020100, //  7,  6,  5,  4,  3,  2,  1,  0
                              0x0);             //  0,  0,  0,  0,  0,  0,  0,  0

   m512 r = a;

   /* standard step - first round normalization */
   m512 carry = srai_i64(r, DIGIT_SIZE);
   carry      = maskz_permutexvar_i8(mask_shift_carry, idxi8, carry);

   r = and_i64(r, mask52);
   r = add_i64(r, carry);

   /* create mask add ONE(1) to slot */
   int k2 = (int)(cmp_i64_mask(mask52, r, _MM_CMPINT_EQ)); /* (r) == 0xF(13) */
   int k1 = (int)(cmp_i64_mask(mask52, r, _MM_CMPINT_LT)); /* (r)  > 0xF(13) */

   k1 = k2 + (k1 << 1);
   k1 ^= k2;

   r = mask_add_i64(r, (mask8)(k1), r, one);

   /* create mask add MINUS ONE(-1) to slot */
   const int cadd = 0x100;

   int ma = (int)(cmp_i64_mask(r, one, _MM_CMPINT_GE));           /* (r) >= 1 */
   int mb = (int)(cmp_i64_mask(r, setzero_i64(), _MM_CMPINT_LT)); /* (r)  < 0 */

   /* add 0x100 - we make a number from which we subtract intentionally more */
   ma += cadd;
   /* we emulate a shift to a neighboring slot,
    * as well as perform masking with 0xFF,
    * so as NOT to get a number greater than from which we will subtract.
    */
   mb = (mb << 1) & 0xFF;

   /* calculate loans */
   const int mc = ma - mb;
   /* after the step above, the problem arises that after subtracting from (ma),
    * we see dips of units (below in response) in those slots that do not need to add -1
    * and these slots can be determined if 3 conditions are met:
    * 1) (ma) == 1
    * 2) (mb) == 0
    * 3) (mc) == 1
    */
   const int mx = ~(ma & (~mb) & mc);
   /* add mask mx AND if there was a suppression of 1 in the slot - add minus 1 */
   const int mask_mone = (mx & mc) | (ma & ~mc);

   r = mask_add_i64(r, (mask8)mask_mone, r, mone);
   r = and_i64(r, mask52);

   return r;
}

IPP_OWN_DEFN(void, ifma_norm52_dual, (m512 pr1[], const m512 a1, m512 pr2[], const m512 a2))
{
   const m512 mask52             = set1_i64(DIGIT_MASK);
   const m512 one                = set1_i64(1ULL);
   const m512 mone               = set1_i64(-1);
   const mask64 mask_shift_carry = 0xFFFFFFFFFFFFFF00;

   const m512 idxi8 = set_i64(0x3736353433323130, // 55, 54, 53, 52, 51, 50, 49, 48
                              0x2f2e2d2c2b2a2928, // 47, 46, 45, 44, 43, 42, 41, 40
                              0x2726252423222120, // 39, 38, 37, 36, 35, 34, 33, 32
                              0x1f1e1d1c1b1a1918, // 31, 30, 29, 28, 27, 26, 25, 24
                              0x1716151413121110, // 23, 22, 21, 20, 19, 18, 17, 16
                              0x0f0e0d0c0b0a0908, // 15, 14, 13, 12, 11, 10,  9,  8
                              0x0706050403020100, //  7,  6,  5,  4,  3,  2,  1,  0
                              0x0);             //  0,  0,  0,  0,  0,  0,  0,  0

   m512 r1 = a1;
   m512 r2 = a2;
   /* one */
   /* 1 */
   m512 carry1 = srai_i64(r1, DIGIT_SIZE);
   carry1      = maskz_permutexvar_i8(mask_shift_carry, idxi8, carry1);
   /* 2 */
   m512 carry2 = srai_i64(r2, DIGIT_SIZE);
   carry2      = maskz_permutexvar_i8(mask_shift_carry, idxi8, carry2);

   /* 1 */
   r1 = and_i64(r1, mask52);
   r1 = add_i64(r1, carry1);
   
   /* 2 */
   r2 = and_i64(r2, mask52);
   r2 = add_i64(r2, carry2);

   /* add one slots */
   /* 1 */
   int k21 = (int)(cmp_i64_mask(mask52, r1, _MM_CMPINT_EQ));
   int k11 = (int)(cmp_i64_mask(mask52, r1, _MM_CMPINT_LT));
   /* 2 */
   int k22 = (int)(cmp_i64_mask(mask52, r2, _MM_CMPINT_EQ));
   int k12 = (int)(cmp_i64_mask(mask52, r2, _MM_CMPINT_LT));

   /* 1 */
   k11 = k21 + (k11 << 1);
   k11 ^= k21;
   /* 2 */
   k12 = k22 + (k12 << 1);
   k12 ^= k22;

   r1 = mask_add_i64(r1, (mask8)(k11), r1, one);
   r2 = mask_add_i64(r2, (mask8)(k12), r2, one);

   /* add minus one in slots */
   const int cadd = 0x100;

   /* 1 */
   int ma1 = (int)(cmp_i64_mask(r1, one, _MM_CMPINT_GE));
   int mb1 = (int)(cmp_i64_mask(r1, setzero_i64(), _MM_CMPINT_LT));
   /* 2 */
   int ma2 = (int)(cmp_i64_mask(r2, one, _MM_CMPINT_GE));
   int mb2 = (int)(cmp_i64_mask(r2, setzero_i64(), _MM_CMPINT_LT));

   /* 1 */
   ma1 += cadd;
   mb1 = (mb1 << 1) & 0xFF;
   /* 2 */
   ma2 += cadd;
   mb2 = (mb2 << 1) & 0xFF;

   /* 1 */
   const int mc1 = ma1 - mb1;
   const int mx1 = ~(ma1 & (~mb1) & mc1);
   /* 2 */
   const int mc2 = ma2 - mb2;
   const int mx2 = ~(ma2 & (~mb2) & mc2);

   const int mask_mone1 = (mx1 & mc1) | (ma1 & ~mc1);
   const int mask_mone2 = (mx2 & mc2) | (ma2 & ~mc2);

   /* 1 */
   r1 = mask_add_i64(r1, (mask8)mask_mone1, r1, mone);
   r1 = and_i64(r1, mask52);
   /* 2 */
   r2 = mask_add_i64(r2, (mask8)mask_mone2, r2, mone);
   r2 = and_i64(r2, mask52);

   *pr1 = r1;
   *pr2 = r2;
   return;
}

#endif // (_IPP32E >= _IPP32E_K1)
