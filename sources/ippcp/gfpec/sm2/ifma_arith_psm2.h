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
#if !defined(_IFMA_ARITH_PSM2_H_)
#define _IFMA_ARITH_PSM2_H_

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_alias_avx512.h"
#include "gfpec/sm2/ifma_defs_sm2.h"
#include "gfpec/ecnist/ifma_norm.h"


/**
 * \brief
 * compute R = (-A) enhanced Montgomery (Gueron modification group operation)
 * \param[in] a value (in radix 2^52)
 * \return fesm2 value (in radix 2^52)
 */
IPP_OWN_DECL(fesm2, fesm2_neg_norm, (const fesm2 a))

/**
 * \brief
 *
 *  Montgomery multiplication
 *
 *   a * b * r mod n, where r = 2^(6*52) mod n
 *
 *  Note: final normalization to 2^52 radix is not performed and shall be
 *        handled separately.
 *
 * \param[in] a first  value (in radix 2^52)
 * \param[in] b second value (in radix 2^52)
 * \return fesm2 not normalization value
 */
IPP_OWN_DECL(fesm2, fesm2_mul, (const fesm2 a, const fesm2 b))

/**
 * \brief
 *
 *  Montgomery multiplication
 *
 *   a * a * r mod n, where r = 2^(6*52) mod n
 *
 *  Note: final normalization to 2^52 radix is not performed and shall be
 *        handled separately.
 *
 * \param[in] a value (in radix 2^52)
 * \return fesm2 not normalization value
 */
__IPPCP_INLINE IPP_OWN_DEFN(fesm2, fesm2_sqr, (const fesm2 a)) {
    return fesm2_mul(a, a);
}

/**
 * \brief
 *
 *  Dual Montgomery multiplication without final normalization to 2^52 radix.
 *  (two independent multiplications)
 *
 *   a1 * b1 * R mod p
 *   a2 * b2 * R mod p, where R = 2^(6*52) mod p
 *
 * \param[out] pr1 ptr first  value no normalization
 * \param[in]  a1  value first  (in radix 2^52)
 * \param[in]  b1  value second (in radix 2^52)
 * \param[out] pr2 ptr second value no normalization
 * \param[in]  a2  value first  (in radix 2^52)
 * \param[in]  b2  value second (in radix 2^52)
 */
IPP_OWN_DECL(void, fesm2_mul_dual, (fesm2 pr1[], const fesm2 a1, const fesm2 b1, fesm2 pr2[], const fesm2 a2, const fesm2 b2))

/**
 * \brief
 *
 *  Dual Montgomery multiplication without final normalization to 2^52 radix.
 *  (two independent multiplications)
 *
 *   a1 * a1 * R mod p
 *   a2 * a2 * R mod p, where R = 2^(6*52) mod p
 *
 * \param[out] pr1 ptr first  value no normalization
 * \param[in]  a1  value (in radix 2^52)
 * \param[out] pr2 ptr second value no normalization
 * \param[in]  a2  value (in radix 2^52)
 */
__IPPCP_INLINE IPP_OWN_DEFN(void, fesm2_sqr_dual, (fesm2 pr1[], const fesm2 a1, fesm2 pr2[], const fesm2 a2)) {
    fesm2_mul_dual(pr1, a1, a1, pr2, a2, a2);
    return;
}

/* R = A + B */
#define fesm2_add_no_red(A, B) add_i64((A), (B))

/* R = A - B */
#define fesm2_sub_no_red(A, B) sub_i64((A), (B))

/**
 * \brief
 * R = A/2
 * \param[in] a value (in radix 2^52)
 * \return fe384 value (in radix 2^52)
 */
IPP_OWN_DECL(fesm2, fesm2_div2_norm, (const fesm2 a))

/**
 * \brief
 *
 *  Modular inverse modulo p.
 *
 *  1/z mod p
 *
 * \param[in] z value  (in radix 2^52)
 * \return fesm2 value (in radix 2^52)
 */
IPP_OWN_DECL(fesm2, fesm2_inv_norm, (const fesm2 z))

/**
 * \brief
 *
 *  Conversion to Montgomery domain modulo p.
 *
 *  a * r mod p, where r = 2^(6*52) mod p
 *
 * \param[in] a value (in radix 2^52)
 * \return fesm2 value in Montgomery domain
 */
IPP_OWN_DECL(fesm2, fesm2_to_mont, (const fesm2 a))

/**
 * \brief
 *
 *  Conversion from Montgomery domain modulo p.
 *
 *  a mod p
 *
 * \param[in] a value (in radix 2^52)
 * \return fesm2 value from Montgomery
 */
IPP_OWN_DECL(fesm2, fesm2_from_mont, (const fesm2 a))

/**
 * \brief
 * convert radix 64 to (in radix 2^52)
 * \param[in] arad64 ptr array size (6)
 * \return fesm2 value in register 52
 */
IPP_OWN_DECL(fesm2, fesm2_convert_radix64_radix52, (const Ipp64u* a))

/**
 * \brief
 * convert (in radix 2^52) to radix 64
 * \param[out] rrad64 ptr array size (6)
 * \param[in]  arad52 value (in radix 2^52)
 */
IPP_OWN_DECL(void, fesm2_convert_radix52_radix64, (Ipp64u * out, const fesm2 a))

#endif // (_IPP32E >= _IPP32E_K1)

#endif // _IFMA_ARITH_PSM2_H_
