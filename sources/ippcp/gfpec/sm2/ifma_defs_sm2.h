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
#if !defined(_IFMA_DEFS_SM2_H_)
#define _IFMA_DEFS_SM2_H_

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_alias_avx512.h"

typedef m512 fesm2;

#define DIGIT_MASK_52 (0xFFFFFFFFFFFFF)
#define DIGIT_SIZE_52 (52)
#define PSM2_LEN52    (5)
#define PSM2_LEN64    (4)

#define REPL8(e) e, e, e, e, e, e, e, e

/* from Montgomery conversion constant
 * one
 */
static const __ALIGN64 Ipp64u PSM2_ONE52[PSM2_LEN52] = {0x1, 0x0, 0x0, 0x0, 0x0};

/* Montgomery(1)
 * r = 2^(PSM2_LEN52*DIGIT_SIZE) mod psm2
 */
/* r = 2^(52*6) mod psm2 */
static const __ALIGN64 Ipp64u PSM2_R[PSM2_LEN52] = {
    0x0000000001000000, 0x000ffff000000010, 0x0000ffffffffffff, 0x0000000000000000, 0x0000010000000000};

/**
 * \brief
 * check is most significant bit
 * \return mask8
 * 0xFF - is equal one
 * 0x00 - is no equal one
 */
__IPPCP_INLINE mask8 sm2_is_msb(const mask8 a) {
    return (mask8)((mask8)0 - (a >> 7));
}

/**
 * \brief
 * check is zero input value
 * \param[in] value
 * \return mask8
 * 0xFF - is zero value
 * 0x00 - no equal zero
 */
__IPPCP_INLINE mask8 sm2_is_zero_i64(const m512 a) {
    const mask8 mask = cmp_i64_mask(a, setzero_i64(), _MM_CMPINT_NE);
    return sm2_is_msb((~mask & (mask - 1)));
}

#define FESM2_LOADU(A)                  maskz_loadu_i64(0x1F, (A))
#define FESM2_IS_ZERO(A)                sm2_is_zero_i64((A))
#define FESM2_CMP_MASK(A, B, ENUM_CMP)  cmp_i64_mask((A), (B), (ENUM_CMP))
#define FESM2_MASK_MOV(R, SRC, MASK, A) (R) = mask_mov_i64((SRC), (MASK), (A))

#endif // (_IPP32E >= _IPP32E_K1)

#endif // _IFMA_DEFS_SM2_H_
