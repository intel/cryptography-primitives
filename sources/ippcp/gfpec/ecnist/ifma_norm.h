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
#ifndef _IFMA_NORM_H_
#define _IFMA_NORM_H_

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "ifma_alias_avx512.h"

/**
 * \brief
 *
 *  Lightweight single-round normalization. Can be used after multiplication or
 *  addition only.
 *
 * \param[in] a ptr value (52 radix and more)
 * \return m512 value  (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_lnorm52, (const m512 a))

/**
 * \brief
 *
 *  Dual variant of ifma_lnorm52() function.
 *
 * \param[out] pr1 ptr first  value (in radix 2^52)
 * \param[in]  a1  value first (52 radix and more)
 * \param[out] pr2 ptr second value (in radix 2^52)
 * \param[in]  a2  ptr value second (52 radix and more)
 */
IPP_OWN_DECL(void, ifma_lnorm52_dual, (m512 pr1[], const m512 a1, m512 pr2[], const m512 a2))

/**
 * \brief
 *
 *  Subtraction single-round normalization. Can be used after subtraction or other.
 *
 * \param[in] a ptr value (52 radix and more)
 * \return m512 value  (in radix 2^52)
 */
IPP_OWN_DECL(m512, ifma_norm52, (const m512 a))

/**
 * \brief
 *
 *  Dual variant of ifma_norm52() function.
 *
 * \param[out] pr1 ptr first  value (in radix 2^52)
 * \param[in]  a1  value first (52 radix and more)
 * \param[out] pr2 ptr second value (in radix 2^52)
 * \param[in]  a2  ptr value second (52 radix and more)
 */
IPP_OWN_DECL(void, ifma_norm52_dual, (m512 pr1[], const m512 a1, m512 pr2[], const m512 a2))

#endif // (_IPP32E >= _IPP32E_K1)

#endif // _IFMA_NORM_H_
