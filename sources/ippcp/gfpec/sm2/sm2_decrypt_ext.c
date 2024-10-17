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

#include "owncp.h"
#include "owndefs.h"
#include "gfpec/sm2/sm2_stuff.h"

#define CHECK_PRIVATE_KEY(KEY)                                 \
   IPP_BAD_PTR1_RET((KEY))                                     \
   IPP_BADARG_RET(!BN_VALID_ID((KEY)), ippStsContextMatchErr)  \
   IPP_BADARG_RET(BN_NEGATIVE((KEY)), ippStsInvalidPrivateKey) \
   /* test if 0 < pPrivateA < Order */                         \
   IPP_BADARG_RET(0 == gfec_CheckPrivateKey((KEY), pEC), ippStsInvalidPrivateKey)

/**
 * @brief
 * Decryption message text based SM2 elliptic curve
 * Implementation based on standard:
 * GM/T 0003.4-2012 SM2
 * Public key cryptographic algorithm SM2 based on elliptic curves
 * Part 4: Public key encryption algorithm
 * @param [out] pOut             message decryption
 * @param [in]  maxOutLen        available message size buffer
 * @param [out] pOutSize         message size fill container
 * 0          - if the function ends with an error,
 * other (>0) - if the function ends with OK
 * @param [in]  pInp             pointer cipher text
 * @param [in]  inpLen           cipher size
 * @param [in]  pPrvKey          private key
 * @param [in]  pEC              context elliptic curve
 * @param [in]  pScratchBuffer   supported buffer
 * @return
 * ippStsNoErr               - successful
 * ippStsNullPtrErr          - if pOut | pOutSize | pInp | pPrvKey | pEC | pScratchBuffer is NULL
 * ippStsContextMatchErr     - if pEC no valid ID | pEC no exists SUBGROUP
 * ippStsNotSupportedModeErr - if pEC no supported (n|p) modulus arithmetic
 * ippStsBadArgErr           - if
 * * maxOutLen < 0
 * * inpLen < (len(PC) + 2*len(x) + len(SM3))
 * ippStsInvalidPrivateKey   - if test is failed 0 < pPrvKey < Order
 *
 */
/* clang-format off */
IPPFUN(IppStatus, ippsGFpECDecryptSM2_Ext, (Ipp8u *pOut, int maxOutLen,
                                            int *pOutSize,
                                            const Ipp8u *pInp, int inpLen,
                                            const IppsBigNumState *pPrvKey,
                                            IppsGFpECState *pEC, Ipp8u *pScratchBuffer))
/* clang-format on */
{

   IPP_BAD_PTR1_RET(pEC);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_SUBGROUP(pEC), ippStsContextMatchErr);

   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC)); /* base P */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(pME), ippStsNotSupportedModeErr);
   gsModEngine *nME = ECP_MONT_R(pEC); /* base N */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(nME), ippStsNotSupportedModeErr);

   const int elemBits  = GFP_FEBITLEN(pME);  /* size Bits */
   const int elemBytes = (elemBits + 7) / 8; /* size Bytes */
   const int elemSize  = GFP_FELEN(pME);     /* size BNU_CHUNK */

   /* buffer */
   IPP_BAD_PTR1_RET(pScratchBuffer)

   /* check cipher text */
   IPP_BAD_PTR1_RET(pInp)
   /* size */
   const int ciph_PC_size   = 1;
   const int ciph_xy_size   = 2 * (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize;
   const int ciph_hash_size = IPP_SM3_DIGEST_BYTESIZE;
   const int min_ciph_size  = ciph_PC_size + ciph_xy_size + ciph_hash_size;
   IPP_BADARG_RET(!(inpLen >= min_ciph_size), ippStsOutOfRangeErr)

   /* message */
   IPP_BAD_PTR1_RET(pOut)
   /* the cipher text condition guarantees a positive or zero maxOutLen */
   const int ciph_msg_size = inpLen - min_ciph_size;
   IPP_BADARG_RET(!(maxOutLen >= ciph_msg_size), ippStsOutOfRangeErr)

   /* out message size */
   IPP_BAD_PTR1_RET(pOutSize)
   /* zeros */
   *pOutSize = 0;

   /* private key */
   CHECK_PRIVATE_KEY(pPrvKey)

   {
      IppStatus sts  = ippStsInvalidPoint; // pointer input if invalid -> status out
      int finitPoint = 0;

      const Ipp8u *pC1_PC = pInp;
      const Ipp8u *pC1_xy = pC1_PC + ciph_PC_size;
      const Ipp8u *pC3    = pC1_xy + ciph_xy_size;
      const Ipp8u *pC2    = pC3 + ciph_hash_size;

      IppsGFpECPoint R;
      cpEcGFpInitPoint(&R, cpEcGFpGetPool(1, pEC), 0, pEC);
      /* step1: extract C1 from C */
      BNU_CHUNK_T *pBuff = cpGFpGetPool(2, pME);
      BNU_CHUNK_T *pC1_x = pBuff;
      BNU_CHUNK_T *pC1_y = pC1_x + elemSize;

      /* copy coordinate point */
      COPY_BNU(pC1_x, (BNU_CHUNK_T *)(pC1_xy), elemSize);
      COPY_BNU(pC1_y, (BNU_CHUNK_T *)(pC1_xy + elemBytes), elemSize);
      /* convert big endian -> little endian */
      cpSM2KE_reverse_inplace((Ipp8u *)pC1_x, elemBytes);
      cpSM2KE_reverse_inplace((Ipp8u *)pC1_y, elemBytes);
      /* convert to Montgomery */
      GFP_METHOD(pME)->encode(pC1_x, pC1_x, pME);
      GFP_METHOD(pME)->encode(pC1_y, pC1_y, pME);

      /* step 2 (standard) - check valid input coordinate x|y */
      finitPoint          = gfec_SetPoint(ECP_POINT_DATA(&R), pC1_x, pC1_y, pEC);
      ECP_POINT_FLAGS(&R) = finitPoint ? (ECP_AFFINE_POINT | ECP_FINITE_POINT) : 0;

      if (finitPoint && (0 != gfec_IsPointOnCurve(&R, pEC))) {
         sts = ippStsNoErr;
         /* step 3 (standard): [db]C1 = (x2,y2) */
         ippsGFpECMulPoint(&R, pPrvKey, &R, pEC, pScratchBuffer);

         BNU_CHUNK_T *pX = pBuff;
         BNU_CHUNK_T *pY = pX + elemSize;

         gfec_GetPoint(pX, pY, &R, pEC);
         GFP_METHOD(pME)->decode(pX, pX, pME);
         GFP_METHOD(pME)->decode(pY, pY, pME);

         cpSM2KE_reverse_inplace((Ipp8u *)pX, elemBytes);
         cpSM2KE_reverse_inplace((Ipp8u *)pY, elemBytes);

         /* step 4 (standard): t = KDF(x2 || y2, klen) */
         KDF_sm3(pOut, ciph_msg_size, (Ipp8u *)pBuff, 2 * elemBytes);

         /* step 5 (standard): M` = C2 (x) t */
         for (int i = 0; i < ciph_msg_size; ++i) {
            pOut[i] = pOut[i] ^ pC2[i];
         }

         /* step 6 (standard): u = Hash(x2 || M` || y2) */
         static IppsHashState_rmf ctx;

         Ipp8u u[IPP_SM3_DIGEST_BYTESIZE];
         ippsHashInit_rmf(&ctx, ippsHashMethod_SM3());
         /* x2 */
         ippsHashUpdate_rmf((Ipp8u *)pX, elemBytes, &ctx);
         /* M */
         ippsHashUpdate_rmf(pOut, ciph_msg_size, &ctx);
         /* y2 */
         ippsHashUpdate_rmf((Ipp8u *)pY, elemBytes, &ctx);
         /* C3 */
         ippsHashFinal_rmf(u, &ctx);

         if (0 == EquBlock(u, pC3, IPP_SM3_DIGEST_BYTESIZE)) {
            PurgeBlock(pOut, ciph_msg_size);
         } else {
            *pOutSize = ciph_msg_size;
         }

         PurgeBlock(u, IPP_SM3_DIGEST_BYTESIZE);
      }

      cpGFpReleasePool(2, pME);
      cpEcGFpReleasePool(1, pEC); /* release R from the pool */
      return sts;
   }
}

#undef CHECK_PRIVATE_KEY
