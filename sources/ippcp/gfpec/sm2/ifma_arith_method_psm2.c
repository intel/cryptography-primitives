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

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/sm2/ifma_arith_method_sm2.h"
#include "gfpec/sm2/ifma_arith_psm2.h"

IPP_OWN_DEFN(ifmaArithMethod*, gsArithGF_psm2_avx512, (void)) {
    static ifmaArithMethod m = {
        /* import_to52 = */ fesm2_convert_radix64_radix52,
        /* export_to64 = */ fesm2_convert_radix52_radix64,
        /* encode      = */ fesm2_to_mont,
        /* decode      = */ fesm2_from_mont,
        /* mul         = */ fesm2_mul,
        /* mul_dual    = */ fesm2_mul_dual,
        /* sqr         = */ fesm2_sqr,
        /* sqr_dual    = */ fesm2_sqr_dual,
        /* norm        = */ ifma_norm52,
        /* norm_dual   = */ ifma_norm52_dual,
        /* lnorm       = */ ifma_lnorm52,
        /* lnorm_dual  = */ ifma_lnorm52_dual,
        /* add         = */ 0,
        /* sub         = */ 0,
        /* neg         = */ fesm2_neg_norm,
        /* div2        = */ fesm2_div2_norm,
        /* inv         = */ fesm2_inv_norm,
        /* red         = */ 0};

    return &m;
}

#endif /* #if (_IPP32E >= _IPP32E_K1) */
