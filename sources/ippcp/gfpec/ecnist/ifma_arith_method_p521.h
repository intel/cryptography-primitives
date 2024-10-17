/*************************************************************************
* Copyright (C) 2017 Intel Corporation
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

#ifndef IFMA_ARITH_METHOD_P521_H
#define IFMA_ARITH_METHOD_P521_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/ecnist/ifma_defs_p521.h"

/* Modular arith methods based on 2^52 radix number representation */
IPP_OWN_FUNPTR(void, ifma_import, (fe521 pr[], const Ipp64u arad64[P521R1_LEN64]))
IPP_OWN_FUNPTR(void, ifma_export, (Ipp64u rrad64[P521R1_LEN64], const fe521 a))
IPP_OWN_FUNPTR(void, ifma_encode, (fe521 pr[], const fe521 a))
IPP_OWN_FUNPTR(void, ifma_decode, (fe521 pr[], const fe521 a))
IPP_OWN_FUNPTR(void, ifma_mul, (fe521 pr[], const fe521 a, const fe521 b))
IPP_OWN_FUNPTR(void, ifma_mul_dual, (fe521 pr1[], const fe521 a1, const fe521 b1, fe521 pr2[], const fe521 a2, const fe521 b2))
IPP_OWN_FUNPTR(void, ifma_sqr, (fe521 pr[], const fe521 a))
IPP_OWN_FUNPTR(void, ifma_sqr_dual, (fe521 pr1[], const fe521 a1, fe521 pr2[], const fe521 a2))
IPP_OWN_FUNPTR(void, ifma_norm, (fe521 pr[], const fe521 a))
IPP_OWN_FUNPTR(void, ifma_norm_dual, (fe521 pr1[], const fe521 a1, fe521 pr2[], const fe521 a2))
IPP_OWN_FUNPTR(void, ifma_lnorm, (fe521 pr[], const fe521 a))
IPP_OWN_FUNPTR(void, ifma_lnorm_dual, (fe521 pr1[], const fe521 a1, fe521 pr2[], const fe521 a2))
IPP_OWN_FUNPTR(void, ifma_add, (fe521 pr[], const fe521 a, const fe521 b))
IPP_OWN_FUNPTR(void, ifma_div2, (fe521 pr[], const fe521 a))
IPP_OWN_FUNPTR(void, ifma_neg, (fe521 pr[], const fe521 a))
IPP_OWN_FUNPTR(void, ifma_inv, (fe521 pr[], const fe521 z))
IPP_OWN_FUNPTR(void, ifma_red, (fe521 pr[], const fe521 a))

typedef struct _ifmaArithMethod_p521 {
   ifma_import import_to52;
   ifma_export export_to64;
   ifma_encode encode;
   ifma_decode decode;
   ifma_mul mul;
   ifma_mul_dual mul_dual;
   ifma_sqr sqr;
   ifma_sqr_dual sqr_dual;
   ifma_norm norm;
   ifma_norm_dual norm_dual;
   ifma_lnorm lnorm;
   ifma_lnorm_dual lnorm_dual;
   ifma_add add;
   ifma_neg neg;
   ifma_div2 div2;
   ifma_inv inv;
   ifma_red red;
} ifmaArithMethod_p521;

/* Pre-defined AVX512IFMA ISA based methods */
#define gsArithGF_p521r1_avx512 OWNAPI(gsArithGF_p521r1_avx512)
IPP_OWN_DECL(ifmaArithMethod_p521 *, gsArithGF_p521r1_avx512, (void))

#define gsArithGF_n521r1_avx512 OWNAPI(gsArithGF_n521r1_avx512)
IPP_OWN_DECL(ifmaArithMethod_p521 *, gsArithGF_n521r1_avx512, (void))

static __NOINLINE void clear_secrets(fe521 *a, fe521 *b, fe521 *c)
{
   if (NULL != a)
      FE521_SET(*a) = m256_setzero_i64();
   if (NULL != b)
      FE521_SET(*b) = m256_setzero_i64();
   if (NULL != c)
      FE521_SET(*c) = m256_setzero_i64();
}

#endif /* #if (_IPP32E >= _IPP32E_K1) */

#endif /* #ifndef IFMA_ARITH_METHOD_P521_H */
