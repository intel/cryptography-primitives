/*************************************************************************
* Copyright (C) 2016 Intel Corporation
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
//     Intel(R) Cryptography Primitives Library
//
//     Context:
//        ippsGFpECSharedSecretDH()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "gfpec/pcpgfpecstuff.h"

/*F*
//    Name: ippsGFpECSharedSecretDHC
//
// Purpose: Compute Shared Secret (Diffie-Hellman)
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pEC
//                               NULL == pPrivateA
//                               NULL == pPublicB
//                               NULL == pShare
//
//    ippStsContextMatchErr      illegal pEC->idCtx
//                               pEC->subgroup == NULL
//                               illegal pPrivateA->idCtx
//                               illegal pPublicB->idCtx
//                               illegal pShare->idCtx
//
//    ippStsRangeErr             not enough room for share key
//
//    ippStsShareKeyErr          (infinity) => z
//
//    ippStsNoErr                no errors
//
// Parameters:
//    pPrivateA        pointer to own   private key
//    pPublicB         pointer to alien public  key
//    pShare           pointer to the shared secret value
//    pEC              pointer to the EC context
//    pScratchBuffer   pointer to the scratch buffer
//
*F*/
IPPFUN(IppStatus, ippsGFpECSharedSecretDH,(const IppsBigNumState* pPrivateA, const IppsGFpECPoint* pPublicB,
                                           IppsBigNumState* pShare,
                                           IppsGFpECState* pEC, Ipp8u* pScratchBuffer))
{
   IppsGFpState *pGF;
   gsModEngine *pGFE;

   /* EC context and buffer */
   IPP_BAD_PTR2_RET(pEC, pScratchBuffer);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_SUBGROUP(pEC), ippStsContextMatchErr);

   pGF  = ECP_GFP(pEC);
   pGFE = GFP_PMA(pGF);

   /* test private (own) key */
   IPP_BAD_PTR1_RET(pPrivateA);
   IPP_BADARG_RET(!BN_VALID_ID(pPrivateA), ippStsContextMatchErr);
   /* test if 0 < pPrivateA < Order */
   IPP_BADARG_RET(0==gfec_CheckPrivateKey(pPrivateA, pEC), ippStsInvalidPrivateKey);

   /* test public (other party) key */
   IPP_BAD_PTR1_RET(pPublicB);
   IPP_BADARG_RET(!ECP_POINT_VALID_ID(pPublicB), ippStsContextMatchErr);
   /* test if pPublicB belongs EC */
   IPP_BADARG_RET(0==gfec_IsPointOnCurve(pPublicB, pEC), ippStsInvalidPoint);

   /* test share secret value */
   IPP_BAD_PTR1_RET(pShare);
   IPP_BADARG_RET(!BN_VALID_ID(pShare), ippStsContextMatchErr);
   IPP_BADARG_RET((BN_ROOM(pShare) < GFP_FELEN(pGFE)), ippStsRangeErr);

   {
      /* init tmp Point */
      IppsGFpECPoint T;
      cpEcGFpInitPoint(/* pPoint = */ &T,
                       /* pData = */ cpEcGFpGetPool(1, pEC),
                       /* flags = */ 0,
                       /* pEC = */ pEC);

      int finite_point = 0;
      const int elmLen = GFP_FELEN(pGFE);
      /* share data */
      BNU_CHUNK_T *pShareData = BN_NUMBER(pShare);
      int nsShare             = BN_ROOM(pShare);

#if (_IPP32E >= _IPP32E_K1)
      if (IsFeatureEnabled(ippCPUID_AVX512IFMA)) {
         switch (ECP_MODULUS_ID(pEC)) {
         case cpID_PrimeP256r1: {
            finite_point = gfec_SharedSecretDH_nistp256_avx512(&T, pPublicB, BN_NUMBER(pPrivateA), BN_SIZE(pPrivateA), pEC, pScratchBuffer);
            if (finite_point) {
               cpGFpElementCopy(pShareData, ECP_POINT_X(&T), elmLen);
               cpGFpElementPad(pShareData + elmLen, nsShare - elmLen, 0);
            }
            goto exit;
            break;
         }
         case cpID_PrimeP384r1: {
            finite_point = gfec_SharedSecretDH_nistp384_avx512(&T, pPublicB, BN_NUMBER(pPrivateA), BN_SIZE(pPrivateA), pEC, pScratchBuffer);
            if (finite_point) {
               cpGFpElementCopy(pShareData, ECP_POINT_X(&T), elmLen);
               cpGFpElementPad(pShareData + elmLen, nsShare - elmLen, 0);
            }
            goto exit;
            break;
         }
         case cpID_PrimeP521r1: {
            finite_point = gfec_SharedSecretDH_nistp521_avx512(&T, pPublicB, BN_NUMBER(pPrivateA), BN_SIZE(pPrivateA), pEC, pScratchBuffer);
            if (finite_point) {
               cpGFpElementCopy(pShareData, ECP_POINT_X(&T), elmLen);
               cpGFpElementPad(pShareData + elmLen, nsShare - elmLen, 0);
            }
            goto exit;
            break;
         }
         case cpID_PrimeTPM_SM2: {
            finite_point = gfec_SharedSecretDH_sm2_avx512(&T, pPublicB, BN_NUMBER(pPrivateA), BN_SIZE(pPrivateA), pEC, pScratchBuffer);
            if (finite_point) {
               cpGFpElementCopy(pShareData, ECP_POINT_X(&T), elmLen);
               cpGFpElementPad(pShareData + elmLen, nsShare - elmLen, 0);
            }
            goto exit;
            break;
         }
         default:
            /* Go to default implementation below */
            break;
         }
      } /* no else */
#endif  // (_IPP32E >= _IPP32E_K1)
      {
         /* T  = [privateA]pPublicB */
         gfec_MulPoint(&T, pPublicB, BN_NUMBER(pPrivateA), BN_SIZE(pPrivateA), /*ECP_ORDBITSIZE(pEC),*/ pEC, pScratchBuffer);
         /* share = T.x */
         IppsGFpElement elm;
         /* Buffer by GFpElement - get in Pool data */
         cpGFpElementConstruct(&elm, cpGFpGetPool(1, pGFE), elmLen);

         finite_point = gfec_GetPoint(GFPE_DATA(&elm), NULL, &T, pEC);

         /* check finit point */
         if (finite_point) {
            /* share = decode(T.x) */
            GFP_METHOD(pGFE)->decode(pShareData, GFPE_DATA(&elm), pGFE);
            cpGFpElementPad(pShareData + elmLen, nsShare - elmLen, 0);
         }

         cpGFpReleasePool(1, pGFE); /* GFpElement */
      }

#if (_IPP32E >= _IPP32E_K1)
exit:
#endif

      if (finite_point) {
         BN_SIGN(pShare) = ippBigNumPOS;
         FIX_BNU(pShareData, nsShare);
         BN_SIZE(pShare) = nsShare;
      }
      cpEcGFpReleasePool(1, pEC); /* ECPoint */
      return finite_point ? ippStsNoErr : ippStsShareKeyErr;
   }
}
