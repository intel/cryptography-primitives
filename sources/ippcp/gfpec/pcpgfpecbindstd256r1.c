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
//     Intel(R) Cryptography Primitives Library
//     EC over GF(p^m) definitinons
//
//     Context:
//        ippsGFpECBindGxyTblStd256r1()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "gfpec/pcpgfpecstuff.h"
#include "gfpec/pcpeccp.h"
#include "gfpec/pcpgfpmethod.h"


static IppStatus cpGFpECBindGxyTbl(const BNU_CHUNK_T* pPrime,
                                   const cpPrecompAP* preComp,
                                   IppsGFpECState* pEC)
{
   IppsGFpState *pGF = ECP_GFP(pEC);
   gsModEngine *pGFE = GFP_PMA(pGF);
   Ipp32u elemLen    = (Ipp32u)GFP_FELEN(pGFE);

   /* test if GF is prime GF */
   IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
   /* test underlying prime value*/
   IPP_BADARG_RET(cpCmp_BNU(pPrime, (cpSize)elemLen, GFP_MODULUS(pGFE), (cpSize)elemLen), ippStsBadArgErr);

   {
      BNU_CHUNK_T *pbp_ec = ECP_G(pEC);
      int cmpFlag;
      BNU_CHUNK_T *pbp_tbl = cpEcGFpGetPool(1, pEC);

      selectAP select_affine_point = preComp->select_affine_point;
      const BNU_CHUNK_T *pTbl      = preComp->pTbl;
      select_affine_point(pbp_tbl, pTbl, 1);

      /* check if EC's and G-table's Base Point is the same */
      cmpFlag = cpCmp_BNU(pbp_ec, (cpSize)elemLen * 2, pbp_tbl, (cpSize)elemLen * 2);

      cpEcGFpReleasePool(1, pEC);

      return cmpFlag ? ippStsBadArgErr : ippStsNoErr;
   }
}

/*F*
// Name: ippsGFpECBindGxyTblStd256r1
//
// Purpose: Enables the use of base point-based pre-computed tables of EC256r1
//
// Returns:                   Reason:
//    ippStsNullPtrErr              NULL == pEC
//
//    ippStsContextMatchErr         invalid pEC->idCtx
//
//    ippStsBadArgErr               pEC is not EC256r1
//
//    ippStsNoErr                   no error
//
// Parameters:
//    pEC        Pointer to the context of the elliptic curve
//
*F*/

IPPFUN(IppStatus, ippsGFpECBindGxyTblStd256r1, (IppsGFpECState * pEC))
{
   IPP_BAD_PTR1_RET(pEC);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);

#if (_IPP32E >= _IPP32E_K1)
   if (IsFeatureEnabled(ippCPUID_AVX512IFMA)) {
      /* ModulusId as well as IFMA-based GF(p) method are assigned in
       * ippsGFpECInitStd* function. If modulusId is not set (i.e. GFp method is
       * not IFMA-based), then bind regular table (not for IFMA implementation).
       */
      if (ECP_MODULUS_ID(pEC) == cpID_PrimeP256r1) {
         ECP_PREMULBP(pEC) = gfpec_precom_nistP256r1_radix52_fun();
         return ippStsNoErr;
      }
   }
#endif

   const cpPrecompAP *precomp = gfpec_precom_nistP256r1_fun();
   IppStatus sts              = cpGFpECBindGxyTbl(secp256r1_p, precomp, pEC);

   /* setup pre-computed g-table and point access function */
   if (ippStsNoErr == sts)
      ECP_PREMULBP(pEC) = precomp;

   return sts;
}
