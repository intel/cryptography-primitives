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

#include "gfpec/pcpgfpecstuff.h"
#include "gfpec/pcpgfpstuff.h"

#include "gfpec/ecnist/ifma_defs.h"
#include "gfpec/ecnist/ifma_ecpoint_p384.h"
#include "gfpec/ecnist/ifma_arith_method.h"

IPP_OWN_DEFN(int, gfec_SharedSecretDH_nistp384_avx512, (IppsGFpECPoint * pR,
                                                        const IppsGFpECPoint *pP,
                                                        const BNU_CHUNK_T *pScalar,
                                                        int scalarLen,
                                                        IppsGFpECState *pEC,
                                                        Ipp8u *pScratchBuffer))
{
   FIX_BNU(pScalar, scalarLen);
   {
      IPP_UNREFERENCED_PARAMETER(pScratchBuffer);

      gsModEngine *pME = GFP_PMA(ECP_GFP(pEC));

      const int orderBits = ECP_ORDBITSIZE(pEC);
      const int orderLen  = BITS_BNU_CHUNK(orderBits);

      ifmaArithMethod *pmeth = (ifmaArithMethod *)GFP_METHOD_ALT(pME);

      ifma_export from_radix52 = pmeth->export_to64;

      /* Mod engine (mod p) */
      ifma_decode p_from_mont = pmeth->decode;

      /* Copy scalar */
      BNU_CHUNK_T *pExtendedScalar = cpGFpGetPool(2, pME);
      cpGFpElementCopyPad(pExtendedScalar, orderLen + 1, pScalar, scalarLen);

      __ALIGN64 P384_POINT_IFMA P52, R52;
      BNU_CHUNK_T *pPool = cpGFpGetPool(3, pME);

      /* Convert point coordinates to a new Montgomery domain */
      recode_point_to_mont52(&P52, ECP_POINT_DATA(pP), pPool, pmeth, pME);

      ifma_ec_nistp384_mul_point(&R52, &P52, (Ipp8u *)pExtendedScalar, orderBits);


      /* Check if the point - point to infinity */
      const mask8 is_zero_z = is_zero_i64(R52.z);
      int finite_point      = ((mask8)0xFF != is_zero_z);

      /* Get X affine coordinate */
      ifma_ec_nistp384_get_affine_coords(&(R52.x), NULL, &R52);

      R52.x = p_from_mont(R52.x);
      from_radix52(ECP_POINT_X(pR), R52.x);

      cpGFpReleasePool(5, pME);

      return finite_point;
   }
}

#endif // IPP32E >= _IPP32E_K1
