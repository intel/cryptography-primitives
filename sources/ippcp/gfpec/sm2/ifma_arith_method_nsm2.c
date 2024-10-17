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
#include "gfpec/sm2/ifma_arith_nsm2.h"

IPP_OWN_DEFN(ifmaArithMethod*, gsArithGF_nsm2_avx512, (void)) {
    static ifmaArithMethod m = {
        /* import_to52 = */ fesm2_convert_radix64_radix52,
        /* export_to64 = */ fesm2_convert_radix52_radix64,
        /* encode      = */ fesm2_to_mont_norder,
        /* decode      = */ fesm2_from_mont_norder,
        /* mul         = */ fesm2_mul_norder,
        /* mul_dual    = */ 0,
        /* sqr         = */ 0,
        /* sqr_dual    = */ 0,
        /* norm        = */ ifma_norm52,
        /* norm_dual   = */ ifma_norm52_dual,
        /* lnorm       = */ ifma_lnorm52,
        /* lnorm_dual  = */ ifma_lnorm52_dual,
        /* add         = */ fesm2_add_norder_norm,
        /* sub         = */ fesm2_sub_norder_norm,
        /* neg         = */ 0,
        /* div2        = */ 0,
        /* inv         = */ fesm2_inv_norder_norm,
        /* red         = */ fesm2_fast_reduction_norder};

    return &m;
}

#endif /* #if (_IPP32E >= _IPP32E_K1) */
