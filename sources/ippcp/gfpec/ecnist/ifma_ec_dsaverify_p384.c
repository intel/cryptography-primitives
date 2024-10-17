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
#include "gfpec/ecnist/ifma_ecpoint_p384.h"

IPP_OWN_DEFN(IppECResult, gfec_VerifyDSA_nistp384_avx512, (const IppsBigNumState* pMsgDigest,
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

   ifmaArithMethod *pmeth = (ifmaArithMethod *)GFP_METHOD_ALT(pME);
   ifmaArithMethod *nmeth = (ifmaArithMethod *)GFP_METHOD_ALT(nME);

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
   m512 msg, signR, signS;
   msg = signR = signS = setzero_i64();

   const int elemLen = GFP_FELEN(pME);

   BNU_CHUNK_T* pPool = cpGFpGetPool(3, pME);
   BNU_CHUNK_T *pBufMsg   = pPool;
   BNU_CHUNK_T *pBufSignR = pPool + elemLen;
   BNU_CHUNK_T *pBufSignS = pPool + 2 * elemLen;

   ZEXPAND_COPY_BNU(pBufMsg, orderLen, BN_NUMBER(pMsgDigest), BN_SIZE(pMsgDigest));
   ZEXPAND_COPY_BNU(pBufSignR, orderLen, BN_NUMBER(pSignR), BN_SIZE(pSignR));
   ZEXPAND_COPY_BNU(pBufSignS, orderLen, BN_NUMBER(pSignS), BN_SIZE(pSignS));

   msg   = to_radix52((Ipp64u *)pBufMsg);
   msg   = n_red(msg); /* reduce just in case */
   signR = to_radix52((Ipp64u *)pBufSignR);
   signS = to_radix52((Ipp64u *)pBufSignS);

   /* Convert public point to proper Montgomery domain and 2^52 radix */
   __ALIGN64 P384_POINT_IFMA pubKey;
   recode_point_to_mont52(&pubKey, ECP_POINT_DATA(pRegPublic), pPool /* 3 elem */, pmeth, pME);

   m512 h, h1, h2;
   h = h1 = h2 = setzero_i64();

   /* h = (signS)^(-1) */
   h = n_to_mont(signS);
   h = n_inv(h);

   /* h1 = msg*h,  h2 = signR*h */
   h1 = n_to_mont(msg);
   h2 = n_to_mont(signR);

   h1 = n_mul(h1, h);
   h2 = n_mul(h2, h);

   h1 = n_from_mont(h1);
   h2 = n_from_mont(h2);

   BNU_CHUNK_T *pExtendedH1 = cpGFpGetPool(2, pME);
   BNU_CHUNK_T *pExtendedH2 = cpGFpGetPool(2, pME);
   BNU_CHUNK_T *pH1         = cpGFpGetPool(1, pME);
   BNU_CHUNK_T *pH2         = cpGFpGetPool(1, pME);

   from_radix52((Ipp64u *)pH1, h1);
   from_radix52((Ipp64u *)pH2, h2);
   cpGFpElementCopyPad(pExtendedH1, orderLen + 1, pH1, orderLen);
   cpGFpElementCopyPad(pExtendedH2, orderLen + 1, pH2, orderLen);

   cpGFpReleasePool(2, pME);    /* pH1, pH2 */

   __ALIGN64 P384_POINT_IFMA P;
   P.x = P.y = P.z = setzero_i64();

   /* P = h1*basePoint + h2*pubKey */
   ifma_ec_nistp384_mul_point(&pubKey, &pubKey, (Ipp8u *)pExtendedH2, orderBits);

   if (ECP_PREMULBP(pEC)) {
      ifma_ec_nistp384_mul_pointbase(&P, (Ipp8u *)pExtendedH1, orderBits);
   } else {
      /* Convert base point to a new Montgomery domain */
      __ALIGN64 P384_POINT_IFMA G52;
      recode_point_to_mont52(&G52, ECP_G(pEC), pPool /* 3 elem */, pmeth, pME);

      ifma_ec_nistp384_mul_point(&P, &G52, (Ipp8u *)pExtendedH1, orderBits);
   }

   ifma_ec_nistp384_add_point(&P, &P, &pubKey);

   /* Get X in affine coordinates */
   ifma_ec_nistp384_get_affine_coords(&(P.x), NULL, &P);

   P.x = p_from_mont(P.x);
   P.x = n_red(P.x);

   const mask8 mask_ok = cmp_i64_mask(P.x, signR, _MM_CMPINT_EQ);
   if ((mask8)0xFF == mask_ok)
      verifyResult = ippECValid;

   cpGFpReleasePool(7, pME);

   return verifyResult;
}

#endif // (_IPP32E >= _IPP32E_K1)
