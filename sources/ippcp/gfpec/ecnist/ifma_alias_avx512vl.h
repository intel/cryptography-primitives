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

#ifndef IFMA_ALIAS_AVX512VL_H
#define IFMA_ALIAS_AVX512VL_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include <immintrin.h>

typedef __m256i m256i;
typedef __mmask8 mask8;
typedef __mmask32 mask32;
typedef __mmask64 mask64;

/* load/store */
#define m256_loadu_i64(A) _mm256_maskz_loadu_epi64(0xFF, (A))
#define m256_maskz_loadu_i64 _mm256_maskz_loadu_epi64
#define m256_storeu_i64(R, A) _mm256_mask_storeu_epi64((R), 0xFF, (A))
#define m256_mask_storeu_i64 _mm256_mask_storeu_epi64
/* cmp */
#define m256_cmp_i64_mask _mm256_cmp_epi64_mask
/* mov */
#define m256_mask_mov_i64 _mm256_mask_mov_epi64
/* set */
#define m256_setzero_i64 _mm256_setzero_si256
#define m256_set_i8 _mm256_set_epi8
#define m256_set_i16 _mm256_set_epi16
#define m256_set_i64 _mm256_set_epi64x
#define m256_set1_i64 _mm256_set1_epi64x
/* shift permutexvar */
#define m256_permutexvar_i8 _mm256_permutexvar_epi8
#define m256_permutexvar_i16 _mm256_permutexvar_epi16
#define m256_maskz_permutexvar_i8 _mm256_maskz_permutexvar_epi8
/* shift logic/arithmetic */
#define m256_srli_i64 _mm256_srli_epi64
#define m256_slli_i64 _mm256_slli_epi64
#define m256_srlv_i64 _mm256_srlv_epi64
#define m256_sllv_i64 _mm256_sllv_epi64
#define m256_srai_i64 _mm256_srai_epi64
#define m256_maskz_srli_i64 _mm256_maskz_srli_epi64
#define m256_maskz_srai_i64 _mm256_maskz_srai_epi64
#define m256_maskz_slli_i64 _mm256_maskz_slli_epi64
#define m256_alignr_i64 _mm256_alignr_epi64
/* and/or */
#define m256_and_i64 _mm256_and_si256
#define m256_or_i64 _mm256_or_si256
/* add/sub */
#define m256_add_i64 _mm256_add_epi64
#define m256_mask_add_i64 _mm256_mask_add_epi64
#define m256_maskz_add_i64 _mm256_maskz_add_epi64
#define m256_sub_i64 _mm256_sub_epi64
#define m256_mask_sub_i64 _mm256_mask_sub_epi64
/* ifma */
#define m256_madd52lo_i64 _mm256_madd52lo_epu64
#define m256_madd52hi_i64 _mm256_madd52hi_epu64
#define m256_maskz_madd52lo_i64 _mm256_maskz_madd52lo_epu64
#define m256_maskz_madd52hi_i64 _mm256_maskz_madd52hi_epu64

#endif // (_IPP32E >= _IPP32E_K1)

#endif
