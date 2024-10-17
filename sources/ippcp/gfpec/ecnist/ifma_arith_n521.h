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

#ifndef IFMA_ARITH_N521_H
#define IFMA_ARITH_N521_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_defs_p521.h"

/**
 * \brief
 * R = (A * B) - in domain n521r1
 * \param[out] pr value no normalization
 * \param[in]  a  first  value (in radix 2^52)
 * \param[in]  b  second value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_amm52_n521, (fe521 pr[], const fe521 a, const fe521 b))

/**
 * \brief
 * R = (A + B) mod n521r1
 * \param[out] pr value (in radix 2^52)
 * \param[in]  a  first  value (in radix 2^52)
 * \param[in]  b  second value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_add52_n521, (fe521 pr[], const fe521 a, const fe521 b))

/**
 * \brief
 * to Montgomery domain
 * \param[out] pr value (in radix 2^52)
 * \param[in]  a  value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_tomont52_n521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * fast reduction order n521r1
 * \param[out] pr value (in radix 2^52)
 * \param[in]  a  value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_fastred52_n521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * from Montgomery domain
 * \param[out] pr value (in radix 2^52)
 * \param[in]  a  value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_frommont52_n521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * inverse R = 1/z
 * \param[out] pr value (in radix 2^52)
 * \param[in]  z  value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_aminv52_n521, (fe521 pr[], const fe521 z))

#endif // (_IPP32E >= _IPP32E_K1)

#endif
