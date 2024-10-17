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

#if !defined(_IFMA_ARITH_N256R1_H_)
#define _IFMA_ARITH_N256R1_H_

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "ifma_alias_avx512.h"

/**
 * \brief
 *
 *  Montgomery multiplication
 *
 *   a * b * R mod n, where R = 2^(6*52) mod n
 *
 * \param[in]  a   first value (in radix 2^52)
 * \param[in]  b   second value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_amm52_n256, (const m512 a, const m512 b))

/**
 * \brief
 *
 *  A + B (mod n)
 *
 * \param[in] a first  value (in radix 2^52)
 * \param[in] b second value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_add52_n256, (const m512 a, const m512 b))

/**
 * \brief
 *
 *  Reduction modulo n (subgroup order).
 *
 *  (a >= n256) ? a - n256 : a
 *
 * \param[in] a value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_fastred52_n256, (const m512 a))

/**
 * \brief
 *
 *  Conversion to Montgomery domain modulo n (subgroup order).
 *
 *  a * R mod n, where R = 2^(6*52) mod n
 *
 * \param[in] a value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_tomont52_n256, (const m512 a))

/**
 * \brief
 *
 *  Conversion from Montgomery domain modulo n (subgroup order).
 *
 *  a mod n
 *
 * \param[in] p value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_frommont52_n256, (const m512 a))

/**
 * \brief
 *
 *  Modular inverse modulo n (subgroup order).
 *
 *  1/z mod n
 *
 * \param[in] z value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_aminv52_n256, (const m512 z))

#endif // (_IPP32E >= _IPP32E_K1)

#endif // _IFMA_ARITH_N256R1_H_
