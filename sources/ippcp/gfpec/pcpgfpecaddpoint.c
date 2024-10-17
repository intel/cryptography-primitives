/*************************************************************************
* Copyright (C) 2010 Intel Corporation
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

/*
//
//  Purpose:
//     Intel(R) Cryptography Primitives Library
//     EC over GF(p) Operations
//
//     Context:
//        ippsGFpECAddPoint()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "gfpec/pcpgfpecstuff.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"

/*F*
// Name: ippsGFpECAddPoint
//
// Purpose: Computes the sum of two points on an elliptic curve
//
// Returns:                   Reason:
//    ippStsNullPtrErr               pP == NULL
//                                   pQ == NULL
//                                   pR == NULL
//                                   pEC == NULL
//
//    ippStsContextMatchErr          invalid pEC->idCtx
//                                   invalid pP->idCtx
//                                   invalid pQ->idCtx
//                                   invalid pR->idCtx
//
//    ippStsOutOfRangeErr            ECP_POINT_FELEN(pP)!=GFP_FELEN()
//                                   ECP_POINT_FELEN(pQ)!=GFP_FELEN()
//                                   ECP_POINT_FELEN(pR)!=GFP_FELEN()
//
//    ippStsNoErr                    no error
//
// Parameters:
//    pP              Pointer to the context of the first elliptic curve point
//    pQ              Pointer to the context of the second elliptic curve point
//    pR              Pointer to the context of the resulting elliptic curve point
//    pEC             Pointer to the context of the elliptic curve
//
*F*/

IPPFUN(IppStatus, ippsGFpECAddPoint,(const IppsGFpECPoint* pP, const IppsGFpECPoint* pQ, IppsGFpECPoint* pR,
                  IppsGFpECState* pEC))
{
   IPP_BAD_PTR4_RET(pP, pQ, pR, pEC);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_POINT_VALID_ID(pP), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_POINT_VALID_ID(pQ), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_POINT_VALID_ID(pR), ippStsContextMatchErr);

   IPP_BADARG_RET(ECP_POINT_FELEN(pP) != GFP_FELEN(GFP_PMA(ECP_GFP(pEC))), ippStsOutOfRangeErr);
   IPP_BADARG_RET(ECP_POINT_FELEN(pQ) != GFP_FELEN(GFP_PMA(ECP_GFP(pEC))), ippStsOutOfRangeErr);
   IPP_BADARG_RET(ECP_POINT_FELEN(pR) != GFP_FELEN(GFP_PMA(ECP_GFP(pEC))), ippStsOutOfRangeErr);

#if (_IPP32E >= _IPP32E_K1)
   if (IsFeatureEnabled(ippCPUID_AVX512IFMA)) {
      switch (ECP_MODULUS_ID(pEC)) {
      case cpID_PrimeP256r1: {
         gfec_AddPoint_nistp256_avx512(pR, pP, pQ, pEC);
         return ippStsNoErr;
      }
      case cpID_PrimeP384r1: {
         gfec_AddPoint_nistp384_avx512(pR, pP, pQ, pEC);
         return ippStsNoErr;
      }
      case cpID_PrimeP521r1: {
         gfec_AddPoint_nistp521_avx512(pR, pP, pQ, pEC);
         return ippStsNoErr;
      }
      case cpID_PrimeTPM_SM2: {
         gfec_AddPoint_sm2_avx512(pR, pP, pQ, pEC);
         return ippStsNoErr;
      }
      default:
         /* Go to default implementation below */
         break;
      }
   }   /* no else */
#endif // (_IPP32E >= _IPP32E_K1)

   if (pP == pQ)
      gfec_DblPoint(pR, pP, pEC);
   else
      gfec_AddPoint(pR, pP, pQ, pEC);

   return ippStsNoErr;
}
