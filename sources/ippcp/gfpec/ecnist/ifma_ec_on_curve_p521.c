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

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/pcpgfpecstuff.h"
#include "gfpec/pcpgfpstuff.h"

#include "gfpec/ecnist/ifma_arith_method_p521.h"
#include "gfpec/ecnist/ifma_ecpoint_p521.h"

IPP_OWN_DEFN(int, gfec_point_on_curve_nistp521_avx512, (const IppsGFpECPoint *pPoint, IppsGFpECState *pEC))
{
   gsModEngine *pME       = GFP_PMA(ECP_GFP(pEC));
   ifmaArithMethod_p521 *pmeth = (ifmaArithMethod_p521 *)GFP_METHOD_ALT(pME);

   BNU_CHUNK_T *pPool = cpGFpGetPool(3, pME);

   __ALIGN64 P521_POINT_IFMA P;

   recode_point_to_mont52(&P, ECP_POINT_DATA(pPoint), pPool /* 3 elem */, pmeth, pME);

   const int onCurve = ifma_ec_nistp521_is_on_curve(&P, /* use_jproj_coord = */ !IS_ECP_AFFINE_POINT(pPoint));

   cpGFpReleasePool(3, pME);
   return onCurve;
}

#endif // (_IPP32E >= _IPP32E_K1)
