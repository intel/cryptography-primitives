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

#include "gfpec/ecnist/ifma_arith_method_p521.h"
#include "gfpec/ecnist/ifma_ecpoint_p521.h"

IPP_OWN_DEFN(IppECResult, gfec_VerifyDSA_nistp521_avx512, (const IppsBigNumState* pMsgDigest,
                                                           const IppsGFpECPoint* pRegPublic,
                                                           const IppsBigNumState* pSignR,
                                                           const IppsBigNumState* pSignS,
                                                           IppsGFpECState* pEC,
                                                           Ipp8u* pScratchBuffer))
{
   IPP_UNREFERENCED_PARAMETER(pScratchBuffer);

   IppECResult verifyResult = ippECInvalidSignature;

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
   ifma_mul    n_mul        = nmeth->mul;
   ifma_inv n_inv           = nmeth->inv;
   ifma_red n_red           = nmeth->red;

   /* Convert input parameters to 2^52 radix */
   fe521 msg, signR, signS;
   FE521_SET(msg) = FE521_SET(signR) = FE521_SET(signS) = m256_setzero_i64();

   const int elemLen = GFP_FELEN(pME);

   BNU_CHUNK_T *pPool     = cpGFpGetPool(3, pME);
   BNU_CHUNK_T *pBufMsg   = pPool;
   BNU_CHUNK_T *pBufSignR = pPool + elemLen;
   BNU_CHUNK_T *pBufSignS = pPool + 2 * elemLen;

   ZEXPAND_COPY_BNU(pBufMsg, orderLen, BN_NUMBER(pMsgDigest), BN_SIZE(pMsgDigest));
   ZEXPAND_COPY_BNU(pBufSignR, orderLen, BN_NUMBER(pSignR), BN_SIZE(pSignR));
   ZEXPAND_COPY_BNU(pBufSignS, orderLen, BN_NUMBER(pSignS), BN_SIZE(pSignS));

   to_radix52(&msg, (Ipp64u *)pBufMsg);
   n_red(&msg, msg); /* reduce just in case */
   to_radix52(&signR, (Ipp64u *)pBufSignR);
   to_radix52(&signS, (Ipp64u *)pBufSignS);

   /* Convert public point to proper Montgomery domain and 2^52 radix */
   __ALIGN64 P521_POINT_IFMA pubKey;
   recode_point_to_mont52(&pubKey, ECP_POINT_DATA(pRegPublic), pPool /* 3 elem */, pmeth, pME);

   fe521 h, h1, h2;
   FE521_SET(h) = FE521_SET(h1) = FE521_SET(h2) = m256_setzero_i64();

   /* h = (signS)^(-1) */
   n_to_mont(&h, signS);
   n_inv(&h, h);

   /* h1 = msg*h,  h2 = signR*h */
   n_to_mont(&h1, msg);
   n_to_mont(&h2, signR);

   n_mul(&h1, h1, h);
   n_mul(&h2, h2, h);

   n_from_mont(&h1, h1);
   n_from_mont(&h2, h2);

   BNU_CHUNK_T *pExtendedH1 = cpGFpGetPool(2, pME);
   BNU_CHUNK_T *pExtendedH2 = cpGFpGetPool(2, pME);
   BNU_CHUNK_T *pH1         = cpGFpGetPool(1, pME);
   BNU_CHUNK_T *pH2         = cpGFpGetPool(1, pME);

   from_radix52((Ipp64u *)pH1, h1);
   from_radix52((Ipp64u *)pH2, h2);
   cpGFpElementCopyPad(pExtendedH1, orderLen + 1, pH1, orderLen);
   cpGFpElementCopyPad(pExtendedH2, orderLen + 1, pH2, orderLen);

   cpGFpReleasePool(2, pME); /* pH1, pH2 */

   __ALIGN64 P521_POINT_IFMA P;
   FE521_SET(P.x) = FE521_SET(P.y) = FE521_SET(P.z) = m256_setzero_i64();

   /* P = h1*basePoint + h2*pubKey */
   ifma_ec_nistp521_mul_point(&pubKey, &pubKey, (Ipp8u *)pExtendedH2, orderBits);

   if (ECP_PREMULBP(pEC)) {
      ifma_ec_nistp521_mul_pointbase(&P, (Ipp8u *)pExtendedH1, orderBits);
   } else {
      /* Convert base point to a new Montgomery domain */
      __ALIGN64 P521_POINT_IFMA G52;
      recode_point_to_mont52(&G52, ECP_G(pEC), pPool /* 3 elem */, pmeth, pME);

      ifma_ec_nistp521_mul_point(&P, &G52, (Ipp8u *)pExtendedH1, orderBits);
   }

   ifma_ec_nistp521_add_point(&P, &P, &pubKey);

   /* Get X in affine coordinates */
   ifma_ec_nistp521_get_affine_coords(&(P.x), NULL, &P);

   p_from_mont(&(P.x), P.x);
   n_red(&(P.x), P.x);

   const mask8 mask_ok = FE521_CMP_MASK(P.x, signR, _MM_CMPINT_EQ);
   if ((mask8)0xF == mask_ok)
      verifyResult = ippECValid;

   cpGFpReleasePool(7, pME);

   return verifyResult;
}

#endif // (_IPP32E >= _IPP32E_K1)
