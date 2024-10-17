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
//        ippsGFpECInitStdSM2()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "gfpec/pcpgfpecstuff.h"
#include "gfpec/pcpeccp.h"

#if (_IPP32E >= _IPP32E_K1)
#include "gfpec/sm2/ifma_arith_method_sm2.h"
#include "gfpec/pcpgfpmethod.h"
#endif // (_IPP32E >= _IPP32E_K1)


static void cpGFpECSetStd(int aLen, const BNU_CHUNK_T* pA,
                          int bLen, const BNU_CHUNK_T* pB,
                          int xLen, const BNU_CHUNK_T* pX,
                          int yLen, const BNU_CHUNK_T* pY,
                          int rLen, const BNU_CHUNK_T* pR,
                          BNU_CHUNK_T h,
                          IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elemLen = GFP_FELEN(pGFE);

   IppsGFpElement elmA, elmB;
   __ALIGN8 IppsBigNumState R;
   __ALIGN8 IppsBigNumState H;

   /* convert A and B coeffs into GF elements */
   cpGFpElementConstruct(&elmA, cpGFpGetPool(1, pGFE), elemLen);
   cpGFpElementConstruct(&elmB, cpGFpGetPool(1, pGFE), elemLen);
   ippsGFpSetElement((Ipp32u*)pA, BITS2WORD32_SIZE(BITSIZE_BNU(pA,aLen)), &elmA, pGF);
   ippsGFpSetElement((Ipp32u*)pB, BITS2WORD32_SIZE(BITSIZE_BNU(pB,bLen)), &elmB, pGF);
   /* and set EC */
   ippsGFpECSet(&elmA, &elmB, pEC);

   /* construct R and H */
   cpConstructBN(&R, rLen, (BNU_CHUNK_T*)pR, NULL);
   cpConstructBN(&H, 1, &h, NULL);
   /* convert GX and GY coeffs into GF elements */
   ippsGFpSetElement((Ipp32u*)pX, BITS2WORD32_SIZE(BITSIZE_BNU(pX,xLen)), &elmA, pGF);
   ippsGFpSetElement((Ipp32u*)pY, BITS2WORD32_SIZE(BITSIZE_BNU(pY,yLen)), &elmB, pGF);
   /* and init EC subgroup */
   ippsGFpECSetSubgroup(&elmA, &elmB, &R, &H, pEC);
   cpGFpReleasePool(2, pGFE);

#if (_IPP32E >= _IPP32E_K1)
      if (IsFeatureEnabled(ippCPUID_AVX512IFMA)) {
         ECP_MONT_R(pEC)->method_alt = gsArithGF_nsm2_avx512();
      }
#endif // (_IPP32E >= _IPP32E_K1)
}

/*F*
// Name: ippsGFpECInitStdSM2
//
// Purpose: Initializes the context of ECSM2
//
// Returns:                   Reason:
//    ippStsNullPtrErr              NULL == pEC
//                                  NULL == pGFp
//
//    ippStsContextMatchErr         invalid pGFp->idCtx
//
//    ippStsBadArgErr               pGFp does not specify the finite field over which the given
//                                  standard elliptic curve is defined
//
//    ippStsNoErr                   no error
//
// Parameters:
//    pGFp       Pointer to the IppsGFpState context of the underlying finite field
//    pEC        Pointer to the context of the elliptic curve being initialized.
//
*F*/

IPPFUN(IppStatus, ippsGFpECInitStdSM2,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   IPP_BADARG_RET( !GFP_VALID_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(tpmSM2_p256_p, BITS_BNU_CHUNK(256), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(256)), ippStsBadArgErr);

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(256), tpmSM2_p256_a,
                    BITS_BNU_CHUNK(256), tpmSM2_p256_b,
                    BITS_BNU_CHUNK(256), tpmSM2_p256_gx,
                    BITS_BNU_CHUNK(256), tpmSM2_p256_gy,
                    BITS_BNU_CHUNK(256), tpmSM2_p256_r,
                    tpmSM2_p256_h,
                    pEC);

      ECP_MODULUS_ID(pEC) = cpID_PrimeTPM_SM2;

      return ippStsNoErr;
   }
}
