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

#include "owndefs.h"

#if (_IPP32E >= _IPP32E_K1)

#include "gfpec/pcpgfpstuff.h"
#include "gfpec/pcpgfpecstuff.h"

#include "gfpec/ecnist/ifma_arith_method.h"
#include "gfpec/ecnist/ifma_ecpoint_p256.h"

IPP_OWN_DEFN(IppsGFpECPoint*, gfec_AddPoint_nistp256_avx512, (IppsGFpECPoint* pR,
                                                              const IppsGFpECPoint* pP,
                                                              const IppsGFpECPoint* pQ,
                                                              IppsGFpECState* pEC))
{
   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC));
   ifmaArithMethod *pmeth = (ifmaArithMethod *)GFP_METHOD_ALT(pME);

   __ALIGN64 P256_POINT_IFMA P, R;

   BNU_CHUNK_T *pPool = cpGFpGetPool(3, pME);

   recode_point_to_mont52(&P, ECP_POINT_DATA(pP), pPool, pmeth, pME);

   if (pP == pQ) {
      ifma_ec_nistp256_dbl_point(&R, &P);
   } else {
      __ALIGN64 P256_POINT_IFMA Q;

      recode_point_to_mont52(&Q, ECP_POINT_DATA(pQ), pPool, pmeth, pME);

      ifma_ec_nistp256_add_point(&R, &P, &Q);
   }

   recode_point_to_mont64(pR, &R, pPool, pmeth, pME);

   cpGFpReleasePool(3, pME);

   ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR) ? 0 : ECP_FINITE_POINT;
   return pR;
}

#endif // (_IPP32E >= _IPP32E_K1)
