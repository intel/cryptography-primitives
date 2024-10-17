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
#if !defined(_IFMA_ARITH_NSM2_H_)
#define _IFMA_ARITH_NSM2_H_

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/sm2/ifma_defs_sm2.h"

/**
 * \brief
 *
 *  Montgomery multiplication
 *
 *   a * b * R mod n, where R = 2^(6*52) mod n
 *
 * \param[in] a  first  value (in radix 2^52)
 * \param[in] b  second value (in radix 2^52)
 * \return value no normalization
 */
IPP_OWN_DECL(fesm2, fesm2_mul_norder, (const fesm2 a, const fesm2 b))

/**
 * \brief
 *
 *  A + B (mod n)
 *
 * \param[in] a  first  value (in radix 2^52)
 * \param[in] b  second value (in radix 2^52)
 * \return value (in radix 2^52)
 */
IPP_OWN_DECL(fesm2, fesm2_add_norder_norm, (const fesm2 a, const fesm2 b))

/**
 * \brief
 *
 *  A + B (mod n)
 *
 * \param[in] a  first  value (in radix 2^52)
 * \param[in] b  second value (in radix 2^52)
 * \return value (in radix 2^52)
 */
IPP_OWN_DECL(fesm2, fesm2_sub_norder_norm, (const fesm2 a, const fesm2 b))

/**
 * \brief
 *
 *  Conversion to Montgomery domain modulo n (subgroup order).
 *
 *  a * R mod n, where R = 2^(6*52) mod n
 *
 * \param[in] a  value (in radix 2^52)
 * \return value (in radix 2^52)
 */
IPP_OWN_DECL(fesm2, fesm2_to_mont_norder, (const fesm2 a))

/**
 * \brief
 *
 *  Reduction modulo n (subgroup order).
 *
 *  (a >= n) ? a - n : a
 *
 * \param[in] a  value (in radix 2^52)
 * \return value (in radix 2^52)
 */
IPP_OWN_DECL(fesm2, fesm2_fast_reduction_norder, (const fesm2 a))

/**
 * \brief
 *
 *  Conversion from Montgomery domain modulo n (subgroup order).
 *
 *  a mod n
 *
 * \param[in] a  value (radix 2^52)
 * \return value (radix 2^52)
 */
IPP_OWN_DECL(fesm2, fesm2_from_mont_norder, (const fesm2 a))

/**
 * \brief
 *
 *  Modular inverse modulo n (subgroup order).
 *
 *  1/z mod n
 *
 * \param[in] z  value (in radix 2^52)
 * \return value (in radix 2^52)
 */
IPP_OWN_DECL(fesm2, fesm2_inv_norder_norm, (const fesm2 z))

#endif // (_IPP32E >= _IPP32E_K1)

#endif // _IFMA_ARITH_NSM2_H_
