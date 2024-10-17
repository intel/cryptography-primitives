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

/*
//
//  Purpose:
//     Cryptography Primitive.
//     Digesting message according to SM3
//
//  Contents:
//        ippsGFpECMessageRepresentationSM2()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"
#include "gfpec/pcpgfpstuff.h"
#include "gfpec/pcpgfpecstuff.h"
#include "gsmodstuff.h"
#include "gfpec/sm2/sm2_stuff.h"


/* clang-format off */
IPPFUN(IppStatus, ippsGFpECMessageRepresentationSM2, (IppsBigNumState * pMsgDigest,
                                                      const Ipp8u* pMsg, int msgLen,
                                                      const Ipp8u* pUserID, int userIDLen,
                                                      const IppsGFpECPoint* pRegPublic,
                                                      IppsGFpECState* pEC, Ipp8u* pScratchBuffer))
/* clang-format on */
{
   IppsGFpState *pGF;
   gsModEngine *pGFE;

   /* check curve data */
   IPP_BAD_PTR1_RET(pEC);
   IPP_BAD_PTR1_RET(pScratchBuffer);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_SUBGROUP(pEC), ippStsContextMatchErr);

   /* check Message */
   IPP_BAD_PTR1_RET(pMsg);
   /* check border (msgLen > 0) */
   IPP_BADARG_RET(!(msgLen > 0), ippStsOutOfRangeErr);

   /* check message digest */
   IPP_BAD_PTR1_RET(pMsgDigest);
   IPP_BADARG_RET(!BN_VALID_ID(pMsgDigest), ippStsContextMatchErr);
   /* make sure bitsize(pMsgDigest) <= bitsize(order) */
   IPP_BADARG_RET(!(cpBN_bitsize(pMsgDigest) <= ECP_ORDBITSIZE(pEC)), ippStsMessageErr);

   /* check User ID */
   IPP_BAD_PTR1_RET(pUserID);
   /* check border (userIDLen > 0) */
   IPP_BADARG_RET(!(userIDLen > 0), ippStsOutOfRangeErr);

   pGF  = ECP_GFP(pEC);
   pGFE = GFP_PMA(pGF);
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(pGFE), ippStsNotSupportedModeErr);

   /* check Public Key */
   IPP_BAD_PTR1_RET(pRegPublic);
   IPP_BADARG_RET(!ECP_POINT_VALID_ID(pRegPublic), ippStsContextMatchErr);
   IPP_BADARG_RET(ECP_POINT_FELEN(pRegPublic) != GFP_FELEN(pGFE), ippStsOutOfRangeErr);

   Ipp8u Za[IPP_SM3_DIGEST_BYTESIZE];
   /* compute Za = SM3( ENTL || ID || a || b || xG || yG || xA || yA ) */
   const IppStatus sts = ippsGFpECUserIDHashSM2((Ipp8u *)Za, pUserID, userIDLen, pRegPublic, pEC, pScratchBuffer);
   if(ippStsNoErr != sts){
      return sts;
   }

   /* e = SM3(Za || M) */
   static IppsHashState_rmf ctx;

   ippsHashInit_rmf(&ctx, ippsHashMethod_SM3());
   /* Za */
   ippsHashUpdate_rmf(Za, sizeof(Za), &ctx);
   /* M */
   ippsHashUpdate_rmf(pMsg, msgLen, &ctx);

   /* final */
   ippsHashFinal_rmf((Ipp8u *)(BN_NUMBER(pMsgDigest)), &ctx);
   BN_SIGN(pMsgDigest) = ippBigNumPOS;

   /* clear stack data */
   PurgeBlock(Za, sizeof(Za));

   return ippStsNoErr;
}
