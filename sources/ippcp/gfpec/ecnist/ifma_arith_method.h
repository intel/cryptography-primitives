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

#ifndef IFMA_ARITH_METHOD_H
#define IFMA_ARITH_METHOD_H

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "owncp.h"
#include "ifma_alias_avx512.h"

/* Modular arith methods based on 2^52 radix number representation */
IPP_OWN_FUNPTR(m512, ifma_import, (const Ipp64u *arad64))
IPP_OWN_FUNPTR(void, ifma_export, (Ipp64u *rrad64, const m512 arad52))
IPP_OWN_FUNPTR(m512, ifma_encode, (const m512 a))
IPP_OWN_FUNPTR(m512, ifma_decode, (const m512 a))
IPP_OWN_FUNPTR(m512, ifma_mul, (const m512 a, const m512 b))
IPP_OWN_FUNPTR(void, ifma_mul_dual, (m512 *r1, const m512 a1, const m512 b1, m512 *r2, const m512 a2, const m512 b2))
IPP_OWN_FUNPTR(m512, ifma_sqr, (const m512 a))
IPP_OWN_FUNPTR(void, ifma_sqr_dual, (m512 * r1, const m512 a1, m512 *r2, const m512 a2))
IPP_OWN_FUNPTR(m512, ifma_norm, (const m512 a))
IPP_OWN_FUNPTR(void, ifma_norm_dual, (m512 *r1, const m512 a1, m512 *r2, const m512 a2))
IPP_OWN_FUNPTR(m512, ifma_lnorm, (const m512 a))
IPP_OWN_FUNPTR(void, ifma_lnorm_dual, (m512 *r1, const m512 a1, m512 *r2, const m512 a2))
IPP_OWN_FUNPTR(m512, ifma_add, (const m512 a, const m512 b))
IPP_OWN_FUNPTR(m512, ifma_sub, (const m512 a, const m512 b))
IPP_OWN_FUNPTR(m512, ifma_neg, (const m512 a))
IPP_OWN_FUNPTR(m512, ifma_div2, (const m512 a))
IPP_OWN_FUNPTR(m512, ifma_inv, (const m512 z))
IPP_OWN_FUNPTR(m512, ifma_red, (const m512 a))

typedef struct _ifmaArithMethod {
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
   ifma_sub sub;
   ifma_neg neg;
   ifma_div2 div2;
   ifma_inv inv;
   ifma_red red;
} ifmaArithMethod;


/* Pre-defined AVX512IFMA ISA based methods */
#define gsArithGF_p256r1_avx512 OWNAPI(gsArithGF_p256r1_avx512)
IPP_OWN_DECL(ifmaArithMethod *, gsArithGF_p256r1_avx512, (void))

#define gsArithGF_n256r1_avx512 OWNAPI(gsArithGF_n256r1_avx512)
IPP_OWN_DECL(ifmaArithMethod *, gsArithGF_n256r1_avx512, (void))

#define gsArithGF_p384r1_avx512 OWNAPI(gsArithGF_p384r1_avx512)
IPP_OWN_DECL(ifmaArithMethod *, gsArithGF_p384r1_avx512, (void))

#define gsArithGF_n384r1_avx512 OWNAPI(gsArithGF_n384r1_avx512)
IPP_OWN_DECL(ifmaArithMethod *, gsArithGF_n384r1_avx512, (void))

static __NOINLINE void clear_secrets(m512 *a, m512 *b, m512 *c)
{
   if (NULL != a)
      *a = setzero_i64();
   if (NULL != b)
      *b = setzero_i64();
   if (NULL != c)
      *c = setzero_i64();
}

#endif /* #if (_IPP32E >= _IPP32E_K1) */

#endif /* #ifndef IFMA_ARITH_METHOD_H */
