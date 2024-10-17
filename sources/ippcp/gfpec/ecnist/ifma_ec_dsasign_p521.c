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

#include "gfpec/ecnist/ifma_ecpoint_p521.h"
#include "gfpec/ecnist/ifma_arith_method_p521.h"
#include "gfpec/ecnist/ifma_alias_avx512vl.h"

IPP_OWN_DEFN(IppStatus, gfec_SignDSA_nistp521_avx512, (const IppsBigNumState *pMsgDigest,
                                                       const IppsBigNumState *pRegPrivate,
                                                       IppsBigNumState *pEphPrivate,
                                                       IppsBigNumState *pSignR,
                                                       IppsBigNumState *pSignS,
                                                       IppsGFpECState *pEC,
                                                       Ipp8u *pScratchBuffer))
{
   IPP_UNREFERENCED_PARAMETER(pScratchBuffer);

   IppStatus sts = ippStsNoErr;

   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC));
   gsModEngine *nME = ECP_MONT_R(pEC);

   const int orderBits = ECP_ORDBITSIZE(pEC);
   const int orderLen  = BITS_BNU_CHUNK(orderBits);

   ifmaArithMethod_p521 *pmeth = (ifmaArithMethod_p521 *)GFP_METHOD_ALT(pME);
   ifmaArithMethod_p521 *nmeth = (ifmaArithMethod_p521 *)GFP_METHOD_ALT(nME);

   ifma_import to_radix52   = pmeth->import_to52;
   ifma_export from_radix52 = pmeth->export_to64;

   /* Mod engine (mod p) */
   ifma_decode p_from_mont    = pmeth->decode;

   /* Mod engine (mod n - subgroup order) */
   ifma_encode n_to_mont    = nmeth->encode;
   ifma_decode n_from_mont  = nmeth->decode;
   ifma_mul n_mul           = nmeth->mul;
   ifma_add n_add           = nmeth->add;
   ifma_inv n_inv           = nmeth->inv;
   ifma_red n_red           = nmeth->red;

   /* Copy scalar */
   BNU_CHUNK_T *pExtendedScalar = cpGFpGetPool(2, pME);
   cpGFpElementCopyPad(pExtendedScalar, orderLen + 1, BN_NUMBER(pEphPrivate), BN_SIZE(pEphPrivate));

   __ALIGN64 P521_POINT_IFMA P;

   if (ECP_PREMULBP(pEC)) {
      ifma_ec_nistp521_mul_pointbase(&P, (Ipp8u *)pExtendedScalar, orderBits);
   } else {
      BNU_CHUNK_T *pPool = cpGFpGetPool(3, pME);

      /* Convert base point to a new Montgomery domain */
      __ALIGN64 P521_POINT_IFMA G52;
      recode_point_to_mont52(&G52, ECP_G(pEC), pPool, pmeth, pME);

      ifma_ec_nistp521_mul_point(&P, &G52, (Ipp8u *)pExtendedScalar, orderBits);

      cpGFpReleasePool(3, pME);
   }

   /*
   // signR = int(ephPublic.x) (mod order)
   */
   /* Extract affine P.x */
   ifma_ec_nistp521_get_affine_coords(&(P.x), NULL, &P);

   p_from_mont(&(P.x), P.x);
   n_red(&(P.x), P.x);

   /*
   // signS = (1/ephPrivate)*(pMsgDigest + private*signR) (mod order)
   */
   fe521 ephPrivateInv;
   FE521_SET(ephPrivateInv) = m256_setzero_i64();
   BNU_CHUNK_T *pTmp        = cpGFpGetPool(1, pME);
   ZEXPAND_COPY_BNU(pTmp, orderLen, BN_NUMBER(pEphPrivate), BN_SIZE(pEphPrivate));
   to_radix52(&ephPrivateInv, pTmp);

   n_to_mont(&ephPrivateInv, ephPrivateInv);
   n_inv(&ephPrivateInv, ephPrivateInv);

   /* Message */
   fe521 msgDigest;
   FE521_SET(msgDigest) = m256_setzero_i64();
   ZEXPAND_COPY_BNU(pTmp, orderLen, BN_NUMBER(pMsgDigest), BN_SIZE(pMsgDigest));
   to_radix52(&msgDigest, pTmp);
   n_red(&msgDigest, msgDigest); /* reduce just in case */
   n_to_mont(&msgDigest, msgDigest);

   /* Regular private key */
   fe521 regPrivate;
   FE521_SET(regPrivate) = m256_setzero_i64();
   ZEXPAND_COPY_BNU(pTmp, orderLen, BN_NUMBER(pRegPrivate), BN_SIZE(pRegPrivate));
   to_radix52(&regPrivate, pTmp);
   n_to_mont(&regPrivate, regPrivate);

   fe521 signS;

   n_to_mont(&signS, P.x);
   n_mul(&signS, regPrivate, signS);
   n_add(&signS, signS, msgDigest);
   n_mul(&signS, signS, ephPrivateInv);
   n_from_mont(&signS, signS);

   const mask8 isZero = (mask8)(FE521_IS_ZERO(signS) | FE521_IS_ZERO(P.x));
   if ((mask8)0xFF == isZero)
      sts = ippStsEphemeralKeyErr;

   from_radix52((Ipp64u *)pTmp, signS);
   BN_SIGN(pSignS) = ippBigNumPOS;
   BN_SIZE(pSignS) = orderLen;
   ZEXPAND_COPY_BNU(BN_NUMBER(pSignS), BN_ROOM(pSignS), pTmp, orderLen);

   from_radix52((Ipp64u *)pTmp, P.x);
   BN_SIGN(pSignR) = ippBigNumPOS;
   BN_SIZE(pSignR) = orderLen;
   ZEXPAND_COPY_BNU(BN_NUMBER(pSignR), BN_ROOM(pSignR), pTmp, orderLen);

   /* Clear secret data */
   clear_secrets(&regPrivate, &(P.x), &signS);

   cpGFpReleasePool(3, pME);

   return sts;
}

#endif // (_IPP32E >= _IPP32E_K1)
