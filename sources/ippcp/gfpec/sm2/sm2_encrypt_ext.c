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

#define CHECK_PUBLIC_KEY(KEY)                                                    \
   IPP_BAD_PTR1_RET((KEY))                                                       \
   IPP_BADARG_RET(!ECP_POINT_VALID_ID((KEY)), ippStsContextMatchErr)             \
   IPP_BADARG_RET(ECP_POINT_FELEN((KEY)) != GFP_FELEN(pME), ippStsOutOfRangeErr) \
   IPP_BADARG_RET(0 == gfec_IsPointOnCurve((KEY), pEC), ippStsInvalidPoint)

#define CHECK_PRIVATE_KEY(KEY)                                 \
   IPP_BAD_PTR1_RET((KEY))                                     \
   IPP_BADARG_RET(!BN_VALID_ID((KEY)), ippStsContextMatchErr)  \
   IPP_BADARG_RET(BN_NEGATIVE((KEY)), ippStsInvalidPrivateKey) \
   /* test if 0 < pPrivateA < Order */                         \
   IPP_BADARG_RET(0 == gfec_CheckPrivateKey((KEY), pEC), ippStsInvalidPrivateKey)

/**
 * @brief
 * Encryption message text based SM2 elliptic curve
 * Implementation based on standard:
 * GM/T 0003.4-2012 SM2
 * Public key cryptographic algorithm SM2 based on elliptic curves
 * Part 4: Public key encryption algorithm
 * @param [out]    pOut             pointer output cipher text
 * @param [in]     maxOutLen        available cipher size container
 * @param [out]    pOutSize         size of the ciphertext filled in the container
 * 0          - if the function ends with an error,
 * other (>0) - if the function ends with OK
 * @param [in]     pInp             pointer message encrypt
 * @param [in]     inpLen           message size encrypt
 * @param [in]     pPublicKey       public key
 * @param [in out] pEhpPublicKey    (!) will be cleared at the end (!) Ephemeral Public Key
 * @param [in out] pEphPrvKey       (!) will be cleared at the end (!) Ephemeral Private Key
 * @param [in]     pEC              context elliptic curve
 * @param [in]     pScratchBuffer   supported buffer
 * @return
 * ippStsNoErr               - successful
 * ippStsNullPtrErr          - if
 * pEC | pScratchBuffer | pInp | pOut | pOutSize | pPublicKey | pEphPublicKey | pEphPrvKey
 * is NULL
 * ippStsContextMatchErr     - if pEC no valid ID | pEC no exists SUBGROUP
 * ippStsNotSupportedModeErr - if pEC no supported (n|p) modulus arithmetic
 * ippStsBadArgErr           - if
 * * inpLen < 0
 * * maxOutLen < (len(PC) + 2*len(x) + len(SM3))
 * ippStsInvalidPrivateKey   - if test is failed 0 < pEphPrvKey < Order
 * ippStsInvalidPoint        - if no in curve Pub Key and Ephemeral Public Key
 */
/* clang-format off */
IPPFUN(IppStatus, ippsGFpECEncryptSM2_Ext, (Ipp8u *pOut, int maxOutLen,
                                            int *pOutSize,
                                            const Ipp8u *pInp, int inpLen,
                                            const IppsGFpECPoint *pPublicKey,
                                            IppsGFpECPoint *pEphPublicKey, IppsBigNumState *pEphPrvKey,
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

   /* check msg size */
   IPP_BAD_PTR1_RET(pInp)
   /* check size */
   IPP_BADARG_RET(!(inpLen >= 0), ippStsOutOfRangeErr)

   /* cipher text */
   IPP_BAD_PTR2_RET(pOut, pOutSize)
   /* init zeros out cipher text */
   *pOutSize = 0;
   /* check size */
   const int ciph_PC_size   = 1;
   const int ciph_xy_size   = (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize * 2;
   const int ciph_hash_size = IPP_SM3_DIGEST_BYTESIZE;
   const int ciph_msg_size  = inpLen;
   IPP_BADARG_RET(!(maxOutLen >= (ciph_PC_size + ciph_xy_size + ciph_msg_size + ciph_hash_size)), ippStsOutOfRangeErr)

   /* check Public | Private key */
   /* private */
   CHECK_PRIVATE_KEY(pEphPrvKey)
   /* public */
   /* step 3: S = [h]Pb -> if Pb valid point and h != 0 -> S valid */
   CHECK_PUBLIC_KEY(pPublicKey)
   CHECK_PUBLIC_KEY(pEphPublicKey)

   /* check that user's Ephemeral Public and Private Keys are related (C1=[k]G) */
   IppsGFpECPoint pTmpPoint;
   cpEcGFpInitPoint(&pTmpPoint, cpEcGFpGetPool(1, pEC), 0, pEC);
   ippsGFpECPublicKey(pEphPrvKey, &pTmpPoint, pEC, pScratchBuffer); // k*G
   int result = gfec_ComparePoint(&pTmpPoint, pEphPublicKey, pEC); // C1 == [k]G ?
   cpEcGFpReleasePool(1, pEC); // Release pool before the possible exit
   IPP_BADARG_RET(!result, ippStsEphemeralKeyErr);

   {
      IppStatus sts = ippStsNoErr;
      /* init pointer C = C1 || C2 || C3 */
      Ipp8u *pC1_PC = pOut;
      Ipp8u *pC1_xy = pC1_PC + ciph_PC_size;
      Ipp8u *pC3    = pC1_xy + ciph_xy_size;
      Ipp8u *pC2    = pC3 + ciph_hash_size;

      /* point elliptic curve */
      IppsGFpECPoint R;
      cpEcGFpInitPoint(&R, cpEcGFpGetPool(1, pEC), 0, pEC);
      BNU_CHUNK_T *pX = NULL;
      BNU_CHUNK_T *pY = NULL;

      /* step 2: C1 = PC || x1 || y1 */
      pC1_PC[0] = 0x04;

      pX = (BNU_CHUNK_T *)(pC1_xy);
      pY = pX + elemSize;

      gfec_GetPoint(pX, pY, pEphPublicKey, pEC);
      GFP_METHOD(pME)->decode(pX, pX, pME);
      GFP_METHOD(pME)->decode(pY, pY, pME);
      cpSM2KE_reverse_inplace((Ipp8u *)pX, elemBytes);
      cpSM2KE_reverse_inplace((Ipp8u *)pY, elemBytes);

      /* step 4: [k]Pb = (x2,y2) */
      ippsGFpECMulPoint(pPublicKey, pEphPrvKey, &R, pEC, pScratchBuffer);
      /* step 5: t = KDF(x2||y2, klen) */
      BNU_CHUNK_T *pBuff = cpGFpGetPool(2, pME);

      pX = pBuff;
      pY = pX + elemSize;

      gfec_GetPoint(pX, pY, &R, pEC);
      GFP_METHOD(pME)->decode(pX, pX, pME);
      GFP_METHOD(pME)->decode(pY, pY, pME);

      cpSM2KE_reverse_inplace((Ipp8u *)pX, elemBytes);
      cpSM2KE_reverse_inplace((Ipp8u *)pY, elemBytes);

      KDF_sm3(pC2, ciph_msg_size, (Ipp8u *)pBuff, 2 * elemBytes);

      /* step 6: C2 = M (x) t */
      for (int i = 0; i < ciph_msg_size; ++i) {
         pC2[i] = pC2[i] ^ pInp[i];
      }

      /* step 7: C3 = Hash(x2 || M || y2) */
      static IppsHashState_rmf ctx;

      ippsHashInit_rmf(&ctx, ippsHashMethod_SM3());
      /* x2 */
      ippsHashUpdate_rmf((Ipp8u *)pX, elemBytes, &ctx);
      /* M */
      ippsHashUpdate_rmf(pInp, ciph_msg_size, &ctx);
      /* y2 */
      ippsHashUpdate_rmf((Ipp8u *)pY, elemBytes, &ctx);
      /* C3 */
      ippsHashFinal_rmf(pC3, &ctx);

      /* set output size data */
      if (sts == ippStsNoErr) {
         *pOutSize = ciph_PC_size + ciph_xy_size + ciph_msg_size + ciph_hash_size;
      }
      /* zeros Public | Private Key */
      cpBN_zero(pEphPrvKey);
      gfec_SetPointAtInfinity(pEphPublicKey);

      cpGFpReleasePool(2, pME);
      cpEcGFpReleasePool(1, pEC); /* release R from the pool */
      return sts;
   }
}

#undef CHECK_PRIVATE_KEY
#undef CHECK_PUBLIC_KEY
