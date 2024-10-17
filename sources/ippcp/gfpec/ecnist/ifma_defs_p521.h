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

#ifndef IFMA_DEFS_P521_H
#define IFMA_DEFS_P521_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_alias_avx512vl.h"

#define DIGIT_MASK_52 (0xFFFFFFFFFFFFF)
#define DIGIT_SIZE_52 (52)

#define P521R1_LEN52 (11)
#define P521R1_LEN64 (9)
#define P521R1_LENFE521_52 (4)
#define P521R1_NUM_CHUNK (3)

typedef m256i fe521[P521R1_NUM_CHUNK];

#define REPL4(a1, a2, a3, a4, a5, a6, a7, a8) a1, a2, a3, a4, a5, a6, a7, a8, \
                                              a1, a2, a3, a4, a5, a6, a7, a8, \
                                              a1, a2, a3, a4, a5, a6, a7, a8, \
                                              a1, a2, a3, a4, a5, a6, a7, a8

/* one */
static const __ALIGN64 Ipp64u P521R1_ONE52[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x1, 0x0, 0x0, 0x0 },
   { 0x0, 0x0, 0x0, 0x0 },
   { 0x0, 0x0, 0x0, 0x0 }
};

#define FE521_LO(A) (A)[0]
#define FE521_MID(A) (A)[1]
#define FE521_HI(A) (A)[2]

#define FE521_SET(A) FE521_LO(A) = FE521_MID(A) = FE521_HI(A)

#define FE521_COPY(R, A)        \
   FE521_LO(R)  = FE521_LO(A);  \
   FE521_MID(R) = FE521_MID(A); \
   FE521_HI(R)  = FE521_HI(A)

#define FE521_LOADU(R, A)                       \
   FE521_LO(R)  = m256_loadu_i64(FE521_LO(A));  \
   FE521_MID(R) = m256_loadu_i64(FE521_MID(A)); \
   FE521_HI(R)  = m256_loadu_i64(FE521_HI(A))

__IPPCP_INLINE mask8 is_msb_m256(const mask8 a)
{
   return ((mask8)0 - (a >> 7));
}

__IPPCP_INLINE mask8 is_zero_m256(const m256i a)
{
   const mask8 mask = _mm256_cmp_epi64_mask(a, m256_setzero_i64(), _MM_CMPINT_NE);
   return is_msb_m256((~mask & (mask - 1)));
}

#define FE521_IS_ZERO(A) (is_zero_m256(m256_or_i64(m256_or_i64(FE521_LO(A), FE521_MID(A)), FE521_HI(A))))

#define FE521_CMP_MASK(A, B, ENUM_CMP) \
   (m256_cmp_i64_mask(FE521_LO(A), FE521_LO(B), (ENUM_CMP)) & m256_cmp_i64_mask(FE521_MID(A), FE521_MID(B), (ENUM_CMP)) & m256_cmp_i64_mask(FE521_HI(A), FE521_HI(B), (ENUM_CMP)))

#define FE521_MASK_MOV(R, SRC, MASK, A)                                    \
   FE521_LO(R)  = m256_mask_mov_i64(FE521_LO(SRC), (MASK), FE521_LO(A));   \
   FE521_MID(R) = m256_mask_mov_i64(FE521_MID(SRC), (MASK), FE521_MID(A)); \
   FE521_HI(R)  = m256_mask_mov_i64(FE521_HI(SRC), (MASK), FE521_HI(A))

#endif // (_IPP32E >= _IPP32E_K1)

#endif // _CP_DEFINE_FE521_K1
