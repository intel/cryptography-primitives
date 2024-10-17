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

#ifndef IFMA_MATH_AVX512_H
#define IFMA_MATH_AVX512_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include <immintrin.h>

typedef __m512i m512;
typedef __mmask8 mask8;
typedef __mmask64 mask64;

/* set */
#define setzero_i64 _mm512_setzero_si512
#define set1_i64 _mm512_set1_epi64

#if 0
/* Note: intrinsics below not available in GCC 8.4 */
#define set_i8 _mm512_set_epi8
#define set_i16 _mm512_set_epi16
#endif

#define set_i64 _mm512_set_epi64

/* load/store */
#define loadu_i64 _mm512_loadu_si512
#define maskz_loadu_i64 _mm512_maskz_loadu_epi64
#define storeu_i64 _mm512_storeu_si512
#define mask_storeu_i64 _mm512_mask_storeu_epi64

/* logical shift */
#define srli_i64 _mm512_srli_epi64
#define srlv_i64 _mm512_srlv_epi64
#define slli_i64 _mm512_slli_epi64
#define sllv_i64 _mm512_sllv_epi64

/* arithmetic shift */
#define srai_i64 _mm512_srai_epi64
#define maskz_srai_i64 _mm512_maskz_srai_epi64
#define maskz_srli_i64 _mm512_maskz_srli_epi64

/* logical */
#define and_i64 _mm512_and_epi64
#define or_i64 _mm512_or_si512

/* add */
#define add_i64 _mm512_add_epi64
#define mask_add_i64 _mm512_mask_add_epi64

/* sub */
#define sub_i64 _mm512_sub_epi64
#define mask_sub_i64 _mm512_mask_sub_epi64

/* cmp */
#define cmp_i64_mask _mm512_cmp_epi64_mask
#define cmp_u64_mask _mm512_cmp_epu64_mask

/* perm */
#define maskz_permutexvar_i8 _mm512_maskz_permutexvar_epi8
#define permutexvar_i8 _mm512_permutexvar_epi8
#define permutexvar_i16 _mm512_permutexvar_epi16

/* move */
#define mask_mov_i64 _mm512_mask_mov_epi64

/* ifma */
#define madd52lo_i64 _mm512_madd52lo_epu64
#define madd52hi_i64 _mm512_madd52hi_epu64

#define alignr_i64 _mm512_alignr_epi64

#endif // if (_IPP32E >= _IPP32E_K1)

#endif
