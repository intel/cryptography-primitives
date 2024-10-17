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

#include "gfpec/ecnist/ifma_arith_method.h"
#include "gfpec/ecnist/ifma_arith_p256.h"
#include "gfpec/ecnist/ifma_arith_n256.h"

IPP_OWN_DEFN(ifmaArithMethod *, gsArithGF_n256r1_avx512, (void))
{
   static ifmaArithMethod m = {
     /* import_to52 = */ convert_radix_to_52x5,
     /* export_to64 = */ convert_radix_to_64x4,
     /* encode      = */ ifma_tomont52_n256,
     /* decode      = */ ifma_frommont52_n256,
     /* mul         = */ ifma_amm52_n256,
     /* mul_dual    = */ 0,
     /* sqr         = */ 0,
     /* sqr_dual    = */ 0,
     /* norm        = */ 0,
     /* norm_dual   = */ 0,
     /* lnorm       = */ 0,
     /* lnorm_dual  = */ 0,
     /* add         = */ ifma_add52_n256,
     /* sub         = */ 0,
     /* neg         = */ 0,
     /* div2        = */ 0,
     /* inv         = */ ifma_aminv52_n256,
     /* red         = */ ifma_fastred52_n256
   };

   return &m;
}

#endif /* #if (_IPP32E >= _IPP32E_K1) */
