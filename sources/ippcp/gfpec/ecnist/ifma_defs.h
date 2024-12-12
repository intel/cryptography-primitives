/*************************************************************************
* Copyright (C) 2019 Intel Corporation
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

#ifndef IFMA_DEFS_H
#define IFMA_DEFS_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "ifma_alias_avx512.h"

/* Internal radix definition */
#define DIGIT_SIZE (52)
#define DIGIT_BASE ((Ipp64u)1 << DIGIT_SIZE)
#define DIGIT_MASK ((Ipp64u)0xFFFFFFFFFFFFF)

/* Number of digit in "digsize" representation of "bitsize" value */
#define NUMBER_OF_DIGITS(bitsize, digsize) (((bitsize) + (digsize)-1) / (digsize))
/* Mask of most significant digit wrt "digsize" representation */
#define MS_DIGIT_MASK(bitsize, digsize) (((int64u)1 << ((bitsize) % (digsize))) - 1)


#define REPL8(e) e, e, e, e, e, e, e, e

/**
 * \brief
 *
 *  Check if bit on corresponding position is 1.
 *  Position counting starts from zero.
 *
 * \return 0xFF - if MSB = 1
 * \return 0x00 - if MSB = 0
 */
__IPPCP_INLINE mask8 check_bit(const mask8 a, int bit)
{
   return (mask8)((mask8)0 - ((a >> bit) & 1u));
}

/**
 * \brief
 *
 *  Check if ZMM register contains all zeroes.
 *
 * \param[in] a value
 * \return 0xFF - if input value is all zeroes
 * \return 0x00 - if input value is not all zeroes
 */
__IPPCP_INLINE mask8 is_zero_i64(const m512 a)
{
   const mask8 mask = cmp_i64_mask(a, setzero_i64(), _MM_CMPINT_NE);
   return check_bit((~mask & (mask - 1u)), 7);
}

#endif // (_IPP32E >= _IPP32E_K1)

#endif // IFMA_DEFS_H
