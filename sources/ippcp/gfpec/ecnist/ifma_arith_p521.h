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

#ifndef IFMA_ARITH_P521_H
#define IFMA_ARITH_P521_H

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_defs_p521.h"

/*
 * p521 = 2^521 - 1
 * in 2^52 radix
 */
static const __ALIGN64 Ipp64u p521_x1[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x0000000000000001,
     0x0000000000000000 }
};
/* 2*p */
static const __ALIGN64 Ipp64u p521_x2[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x000FFFFFFFFFFFFE,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x0000000000000003,
     0x0000000000000000 }
};
/* 4*p */
static const __ALIGN64 Ipp64u p521_x4[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x000FFFFFFFFFFFFC,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x0000000000000007,
     0x0000000000000000 }
};
/* 6*p */
static const __ALIGN64 Ipp64u p521_x6[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x000FFFFFFFFFFFFA,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000000000000000B,
     0x0000000000000000 }
};
/* 8*p */
static const __ALIGN64 Ipp64u p521_x8[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x000FFFFFFFFFFFF8,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF },
   { 0x000FFFFFFFFFFFFF,
     0x000FFFFFFFFFFFFF,
     0x000000000000000F,
     0x0000000000000000 }
};
/* Montgomery(1)
 * r = 2^(P521_LEN52*DIGIT_SIZE) mod p521
 */
static const __ALIGN64 Ipp64u P521R1_R52[P521R1_NUM_CHUNK][P521R1_LENFE521_52] = {
   { 0x0008000000000000,
     0x0000000000000000,
     0x0000000000000000,
     0x0000000000000000 },
   { 0x0000000000000000,
     0x0000000000000000,
     0x0000000000000000,
     0x0000000000000000 },
   { 0x0000000000000000,
     0x0000000000000000,
     0x0000000000000000,
     0x0000000000000000 }
};

/**
 * \brief
 * normalization input fe521 to (in radix 2^52)
 * \param[out] pr ptr value (in radix 2^52)
 * \param[in]  a  value (52 radix or more)
 */
IPP_OWN_DECL(void, ifma_norm52_p521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * duplicate normalization input double fe521 to (in radix 2^52)
 * \param[out] pr1 ptr first value (in radix 2^52)
 * \param[in]  a1  value first (52 radix or more)
 * \param[out] pr2 ptr second value (in radix 2^52)
 * \param[in]  a2  value second (52 radix or more)
 */
IPP_OWN_DECL(void, ifma_norm52_dual_p521, (fe521 pr1[], const fe521 a1, fe521 pr2[], const fe521 a2))

/**
 * \brief
 * light (mul|add only) normalization input fe521 to (in radix 2^52)
 * \param[out] pr ptr value (in radix 2^52)
 * \param[in]  a  value (52 radix or more)
 */
IPP_OWN_DECL(void, ifma_lnorm52_p521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * light (mul|add only) duplicate normalization input double fe521 to (in radix 2^52)
 * \param[out] pr1 ptr first value (in radix 2^52)
 * \param[in]  a1  value first (52 radix or more)
 * \param[out] pr2 ptr second value (in radix 2^52)
 * \param[in]  a2  value second (52 radix or more)
 */
IPP_OWN_DECL(void, ifma_lnorm52_dual_p521, (fe521 pr1[], const fe521 a1, fe521 pr2[], const fe521 a2))

/**
 * \brief
 * R = (A * B) - no normalization
 * \param[out] pr ptr value
 * \param[in]  a  first  value (in radix 2^52)
 * \param[in]  b  second value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_amm52_p521, (fe521 pr[], const fe521 a, const fe521 b))

/**
 * \brief
 * duplicate mul (R = A * B - no normalization) input double complect
 * \param[out] pr1 ptr first value no normalization
 * \param[in]  a1  value first  (in radix 2^52)
 * \param[in]  b1  value second (in radix 2^52)
 * \param[out] pr2 ptr second value no normalization
 * \param[in]  a2  value first  (in radix 2^52)
 * \param[in]  b2  value second (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_amm52_dual_p521, (fe521 pr1[], const fe521 a1, const fe521 b1, fe521 pr2[], const fe521 a2, const fe521 b2))

/**
 * \brief
 * R = A/2 - with normalization
 * \param[out] pr ptr value (in radix 2^52)
 * \param[in]  a  value (52 radix or more)
 */
IPP_OWN_DECL(void, ifma_half52_p521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * compute R = (-A) enhanced Montgomery (Gueron modification group operation)
 * \param[out] pr ptr value (in radix 2^52)
 * \param[in]  a  value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_neg52_p521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * to Montgomery domain (in radix 2^52)
 * \param[out] pr ptr value (in radix 2^52) in Montgomery domain
 * \param[in]  a  value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_tomont52_p521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * from Montgomery domain (in radix 2^52)
 * \param[out] pr ptr value (in radix 2^52) from Montgomery domain
 * \param[in]  a  value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_frommont52_p521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * R = 1/Z
 * \param[out] pr ptr value (in radix 2^52)
 * \param[in]  z  value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_aminv52_p521, (fe521 pr[], const fe521 z))

/**
 * \brief
 * convert radix 64 to (in radix 2^52)
 * \param[out] pr     ptr value (in radix 2^52)
 * \param[in]  arad64 ptr array size (9) - 521 bit
 */
IPP_OWN_DECL(void, convert_radix_to_52_p521, (fe521 pr[], const Ipp64u arad64[P521R1_LEN64]))

/**
 * \brief
 * convert (in radix 2^52) to radix 64
 * \param[out] rrad64 ptr array size (9) - 521 bit
 * \param[in]  a      value (in radix 2^52)
 */
IPP_OWN_DECL(void, convert_radix_to_64_p521, (Ipp64u rrad64[P521R1_LEN64], const fe521 a))

/**
 * \brief
 * R = (A * A) - no normalization
 * \param[out] pr ptr value
 * \param[in]  a  first  value (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_ams52_p521, (fe521 pr[], const fe521 a))

/**
 * \brief
 * duplicate sqr (R = A * A - no normalization) input double complect
 * \param[out] pr1 ptr first value no normalization
 * \param[in]  a1  value first  (in radix 2^52)
 * \param[out] pr2 ptr second value no normalization
 * \param[in]  a2  value first  (in radix 2^52)
 */
IPP_OWN_DECL(void, ifma_ams52_dual_p521, (fe521 pr1[], const fe521 a1, fe521 pr2[], const fe521 a2))

/* R = (A + B) */
#define fe521_add_no_red(R, A, B)                           \
   FE521_LO(R)  = m256_add_i64(FE521_LO(A), FE521_LO(B));   \
   FE521_MID(R) = m256_add_i64(FE521_MID(A), FE521_MID(B)); \
   FE521_HI(R)  = m256_add_i64(FE521_HI(A), FE521_HI(B))

/* R = (A - B) */
#define fe521_sub_no_red(R, A, B)                           \
   FE521_LO(R)  = m256_sub_i64(FE521_LO(A), FE521_LO(B));   \
   FE521_MID(R) = m256_sub_i64(FE521_MID(A), FE521_MID(B)); \
   FE521_HI(R)  = m256_sub_i64(FE521_HI(A), FE521_HI(B))

#endif // (_IPP32E >= _IPP32E_K1)

#endif
