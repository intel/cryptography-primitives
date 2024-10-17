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

#include "gfpec/ecnist/ifma_ecpoint_p521.h"
#include "gfpec/ecnist/ifma_arith_p521.h"
#include "gfpec/ecnist/ifma_arith_method_p521.h"

IPP_OWN_DEFN(IppsGFpECPoint*, gfec_PubKey_nist521_avx512, (IppsGFpECPoint * pR,
                                                           const BNU_CHUNK_T* pScalar,
                                                           int scalarLen, IppsGFpECState* pEC,
                                                           Ipp8u* pScratchBuffer))
{
   FIX_BNU(pScalar, scalarLen);
   {
      IPP_UNREFERENCED_PARAMETER(pScratchBuffer);

      gsModEngine *pME = GFP_PMA(ECP_GFP(pEC));
      gsModEngine *nME = ECP_MONT_R(pEC);

      const int orderBits = ECP_ORDBITSIZE(pEC);
      const int orderLen  = BITS_BNU_CHUNK(orderBits);

      ifmaArithMethod_p521 *pmeth = (ifmaArithMethod_p521 *)GFP_METHOD_ALT(pME);

      BNU_CHUNK_T *pPool = cpGFpGetPool(5, nME);
      BNU_CHUNK_T *pExtendedScalar = pPool;
      BNU_CHUNK_T *pPointPool = pExtendedScalar + 2 * GFP_FELEN(pME);

      /* Copy scalar */
      cpGFpElementCopyPad(pExtendedScalar, orderLen + 1, pScalar, scalarLen);

      __ALIGN64 P521_POINT_IFMA R;
      FE521_SET(R.x) = FE521_SET(R.y) = FE521_SET(R.z) = m256_setzero_i64();

      if (ECP_PREMULBP(pEC)) {
         ifma_ec_nistp521_mul_pointbase(&R, (Ipp8u *)pExtendedScalar, orderBits);
      } else {
         /* Convert base point to a new Montgomery domain */
         __ALIGN64 P521_POINT_IFMA G52;
         recode_point_to_mont52(&G52, ECP_G(pEC), pPointPool /* 3 elem */, pmeth, pME);

         ifma_ec_nistp521_mul_point(&R, &G52, (Ipp8u *)pExtendedScalar, orderBits);
      }

      recode_point_to_mont64(pR, &R, pPointPool /* 3 elem */, pmeth, pME);

      cpGFpReleasePool(5, nME);

      ECP_POINT_FLAGS(pR) = gfec_IsPointAtInfinity(pR) ? 0 : ECP_FINITE_POINT;
      return pR;
   }
}

#endif // (_IPP32E >= _IPP32E_K1)
