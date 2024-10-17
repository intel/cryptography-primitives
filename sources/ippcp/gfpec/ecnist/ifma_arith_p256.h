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

#if !defined(_IFMA_ARITH_P256R1_H_)
#define _IFMA_ARITH_P256R1_H_

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "ifma_alias_avx512.h"
#include "gfpec/ecnist/ifma_norm.h"

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
 * \param[in]  a   first value (in radix 2^52)
 * \param[in]  b   second value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_amm52_p256, (const m512 a, const m512 b))

/**
 * \brief
 *
 *  Dual variant of ifma_amm52_p256() function.
 *
 * \param[out] r1  a1 * b1 mod p
 * \param[in]  a1  first  value (in radix 2^52)
 * \param[in]  b1  second value (in radix 2^52)
 * \param[out] r2  a2 * b2 mod p
 * \param[in]  a2  first  value (in radix 2^52)
 * \param[in]  b2  second value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_amm52_dual_p256, (m512 *r1, const m512 a1, const m512 b1, m512 *r2, const m512 a2, const m512 b2))

/**
 * \brief
 *
 *  A * A
 *
 *  Note: final normalization to 2^52 radix is not performed and shall be
 *        handled separately.
 *
 * \param[in]  a   value (in radix 2^52)
 */
__IPPCP_INLINE IPP_OWN_DEFN(m512, ifma_ams52_p256, (const m512 a))
{
   return ifma_amm52_p256(a, a);
}

/**
 * \brief
 *
 *  Dual variant of ifma_ams52_p256() function.
 *
 * \param[out] r1
 * \param[in]  a1  value (in radix 2^52)
 * \param[out] r2
 * \param[in]  a2  value (in radix 2^52)
 */
__IPPCP_INLINE IPP_OWN_DEFN(void, ifma_ams52_dual_p256, (m512 * r1, const m512 a1, m512 *r2, const m512 a2))
{
   ifma_amm52_dual_p256(r1, a1, a1, r2, a2, a2);
   return;
}

/**
 * \brief
 *
 *  A / 2
 *
 * \param[in]  a  value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_half52_p256, (const m512 a))

/**
 * \brief
 *
 *  Modular inverse modulo p.
 *
 *  1/z mod p
 *
 * \param[in] z value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_aminv52_p256, (const m512 z))

/**
 * \brief
 *
 *  (-A) mod p
 *
 * \param[in] a input value
 */
IPP_OWN_DECL(m512, ifma_neg52_p256, (const m512 a))

/**
 * \brief
 *
 *  Conversion to Montgomery domain modulo p.
 *
 *  a * r mod p, where r = 2^(6*52) mod p
 *
 * \param[in] a value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_tomont52_p256, (const m512 a))

/**
 * \brief
 *
 *  Conversion from Montgomery domain modulo p.
 *
 *  a mod p
 *
 * \param[in] a value (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_frommont52_p256, (const m512 a))

/* =====================================================================================  */
/* =====================================================================================  */

/**
 * \brief
 *
 *  Convert to radix 2^52 from radix 2^64.
 *
 * \param[in] pa   pointer to array of 4 64-bit chunks
 */
IPP_OWN_DECL(m512, convert_radix_to_52x5, (const Ipp64u *pa))

/**
 * \brief
 *
 *  Convert to radix 2^64 from radix 2^52.
 *
 * \param[out] pr   pointer to array of 4 64-bit chunks
 * \param[in]  a    array of 5 64-bit chunks
 */
IPP_OWN_DECL(void, convert_radix_to_64x4, (Ipp64u * rrad64, const m512 arad52))

#endif // (_IPP32E >= _IPP32E_K1)

#endif // _IFMA_ARITH_P256R1_H_
