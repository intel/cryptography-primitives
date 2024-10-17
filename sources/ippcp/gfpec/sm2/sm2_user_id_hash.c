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

#include "owndefs.h"
#include "owncp.h"
#include "gfpec/pcpgfpstuff.h"
#include "gfpec/pcpgfpecstuff.h"
#include "gfpec/sm2/sm2_stuff.h"


/**
 * @brief ippsGFpECUserIDHashSM2
 * compute digest Za = SM3( ENTL||IDA||a||b||Gx||Gy||Px||Py)
 * @param [out] pZaDigest      digest Za
 * @param [in]  pUserID        user ID data
 * @param [in]  userIDLen      length user ID data
 * @param [in]  pPublicKey     public key
 * @param [in]  pEC            context Elliptic Curve
 * @param [in]  pScratchBuffer supported buffer
 * @return
 * ippStsNoErr               - successful
 * ippStsNullPtrErr          - if pEC | pUserID | pPublicKey is NULL
 * ippStsContextMatchErr     - if pEC no valid ID | pEC | ID pPublic Key no exists SUBGROUP
 * ippStsNotSupportedModeErr - if pEC no supported (n|p) modulus arithmetic
 * ippStsInvalidPoint        - if no in curve Pub Key
 * ippStsBadArgErr           - if userIDLen <= 0 or the number representing the userIDLen in bits 
 *                             exceed two bytes (user_id_len*8 > 0xFFFF)
 * ippStsOutOfRangeErr       - if userIDLen <= 0 or public key length is out of range
 */
/* clang-format off */
IPPFUN(IppStatus, ippsGFpECUserIDHashSM2, (Ipp8u * pZaDigest,
                                           const Ipp8u* pUserID, int userIDLen,
                                           const IppsGFpECPoint* pPublicKey,
                                           IppsGFpECState* pEC, Ipp8u* pScratchBuffer))
/* clang-format on */
{

   /* check curve data */
   IPP_BAD_PTR1_RET(pEC)
   IPP_BAD_PTR1_RET(pScratchBuffer)
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr)
   IPP_BADARG_RET(!ECP_SUBGROUP(pEC), ippStsContextMatchErr)

   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC));
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(pME), ippStsNotSupportedModeErr)

   /* check Za return */
   IPP_BAD_PTR1_RET(pZaDigest)

   /* check User ID */
   IPP_BAD_PTR1_RET(pUserID)
   /* check border (userIDLen > 0) */
   IPP_BADARG_RET(!(userIDLen > 0), ippStsOutOfRangeErr);

   /* check Public Key */
   IPP_BAD_PTR1_RET(pPublicKey)
   IPP_BADARG_RET(!ECP_POINT_VALID_ID(pPublicKey), ippStsContextMatchErr)
   IPP_BADARG_RET(ECP_POINT_FELEN(pPublicKey) != GFP_FELEN(pME), ippStsOutOfRangeErr)
   IPP_BADARG_RET(0 == gfec_IsPointOnCurve(pPublicKey, pEC), ippStsInvalidPoint);

   IppStatus ret = ippStsNoErr;

   const int elemBits  = GFP_FEBITLEN(pME);  /* size Bits */
   const int elemBytes = (elemBits + 7) / 8; /* size Bytes */
   const int elemLen   = GFP_FELEN(pME);     /* size BNU_CHUNK */

   BNU_CHUNK_T *pDataBuff = cpGFpGetPool(6, pME);
   /* param curve : a,b,Gx,Gy */
   BNU_CHUNK_T *pA  = pDataBuff;
   BNU_CHUNK_T *pB  = pDataBuff + 1 * elemLen;
   BNU_CHUNK_T *pGx = pDataBuff + 2 * elemLen;
   BNU_CHUNK_T *pGy = pDataBuff + 3 * elemLen;
   /* Public X | Y */
   BNU_CHUNK_T *pX = pDataBuff + 4 * elemLen;
   BNU_CHUNK_T *pY = pDataBuff + 5 * elemLen;

   /* get affine coordinate X | Y */
   gfec_GetPoint(/* pX = */ pX, /* pY = */ pY, /* pPoint = */ pPublicKey, /* pEC = */ pEC);

   /* decode */
   GFP_METHOD(pME)->decode(pX, pX, pME);
   GFP_METHOD(pME)->decode(pY, pY, pME);
   GFP_METHOD(pME)->decode(pA, ECP_A(pEC), pME);
   GFP_METHOD(pME)->decode(pB, ECP_B(pEC), pME);
   GFP_METHOD(pME)->decode(pGx, ECP_G(pEC), pME);
   GFP_METHOD(pME)->decode(pGy, ECP_G(pEC) + elemLen, pME);

   /* convert Little Endian to Big Endian */
   cpSM2KE_reverse_inplace((Ipp8u *)pX, elemBytes);  /* X */
   cpSM2KE_reverse_inplace((Ipp8u *)pY, elemBytes);  /* Y */
   cpSM2KE_reverse_inplace((Ipp8u *)pA, elemBytes);  /* a */
   cpSM2KE_reverse_inplace((Ipp8u *)pB, elemBytes);  /* b */
   cpSM2KE_reverse_inplace((Ipp8u *)pGx, elemBytes); /* Gx */
   cpSM2KE_reverse_inplace((Ipp8u *)pGy, elemBytes); /* Gy */

   /* create hash */
   ret = computeZa_user_id_hash_sm2(pZaDigest,
                                    /* p_user_id = */ pUserID,
                                    /* user_id_len = */ userIDLen,
                                    /* elem_len = */ elemBytes,
                                    /* a = */ (Ipp8u *)pA,
                                    /* b = */ (Ipp8u *)pB,
                                    /* Gx = */ (Ipp8u *)pGx,
                                    /* Gy = */ (Ipp8u *)pGy,
                                    /* px = */ (Ipp8u *)pX,
                                    /* py = */ (Ipp8u *)pY);

   cpGFpReleasePool(6, pME);

   return ret;
}
