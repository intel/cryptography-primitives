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

#ifndef IFMA_ARITH_METHOD_SM2_H_
#define IFMA_ARITH_METHOD_SM2_H_

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "owncp.h"
#include "gfpec/ecnist/ifma_alias_avx512.h"
#include "gfpec/ecnist/ifma_arith_method.h"

/* Pre-defined AVX512IFMA ISA based methods */
#define gsArithGF_psm2_avx512 OWNAPI(gsArithGF_psm2_avx512)
IPP_OWN_DECL(ifmaArithMethod*, gsArithGF_psm2_avx512, (void))

#define gsArithGF_nsm2_avx512 OWNAPI(gsArithGF_nsm2_avx512)
IPP_OWN_DECL(ifmaArithMethod*, gsArithGF_nsm2_avx512, (void))

#endif /* #if (_IPP32E >= _IPP32E_K1) */

#endif /* #ifndef IFMA_ARITH_METHOD_SM2_H_ */
