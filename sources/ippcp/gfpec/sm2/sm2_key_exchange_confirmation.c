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
#include "gfpec/sm2/sm2_key_exchange_method.h"
#include "gfpec/sm2/sm2_stuff.h"

/**
 * @brief ippsGFpECKeyExchangeSM2_Confirm
 * this step Optional in protocol SM2 Key Exchange - Confirmation Peer data
 * see standard:
 * [GBT.32918.3-2016] Public Key cryptographic algorithm SM2 based on elliptic curves
 * Part 3: Key exchange protocol
 * 6.2 Process of key exchange protocol
 * stack compute[standard link]:
 *                                                                       [user  A| user  B]
 * 8) S(1/2) = SM3( 0x0(2/3) || y(u/v) || tmp_p )                        [step  9| step 10]
 * when tmp_p - precomute in SharedKey step
 * @param [in]  pSPeer  S(b/a) peer data confirmation
 * @param [out] pStatus status confirmation
 * 1 is successful or 0 is bad confirmation
 * @param [in]  pKE     constrex Key Exchange
 * @return
 * ippStsNoErr               - successful
 * ippStsNullPtrErr          - if pEC | pKE | pSPeer | pStatus is NULL
 * ippStsContextMatchErr     - if pEC no valid ID | pEC no exists SUBGROUP
 * ippStsNotSupportedModeErr - if pEC no supported (n|p) modulus arithmetic
 * ippStsRangeErr            - if BitSize(pEC) < IPP_SM3_DIGEST_BITSIZE
 * ippStsBadArgErr           - if role(pKE) no equal ippKESM2Requester|ippKESM2Responder
 */
/* clang-format off */
IPPFUN(IppStatus, ippsGFpECKeyExchangeSM2_Confirm, (const Ipp8u pSPeer[IPP_SM3_DIGEST_BYTESIZE],
                                                    int* pStatus,
                                                    IppsGFpECKeyExchangeSM2State* pKE))
/* clang-format on */
{
   /* check Key Exchange */
   IPP_BAD_PTR1_RET(pKE);
   /* check id */
   IPP_BADARG_RET(!EC_SM2_KEY_EXCH_VALID_ID(pKE), ippStsContextMatchErr);
   /* check User Role */
   const IppsKeyExchangeRoleSM2 role = EC_SM2_KEY_EXCH_ROLE(pKE);
   IPP_BADARG_RET(((ippKESM2Requester != role) && (ippKESM2Responder != role)), ippStsBadArgErr);

   /* check Elliptic Curve */
   IppsGFpECState *pEC = EC_SM2_KEY_EXCH_EC(pKE);

   IPP_BAD_PTR1_RET(pEC);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_SUBGROUP(pEC), ippStsContextMatchErr);

   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC)); /* base P */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(pME), ippStsNotSupportedModeErr);
   gsModEngine *nME = ECP_MONT_R(pEC); /* base N */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(nME), ippStsNotSupportedModeErr);
   /* check bitsize >= SM3_DIGSET */
   IPP_BADARG_RET(!(ECP_ORDBITSIZE(pEC) >= IPP_SM3_DIGEST_BITSIZE), ippStsRangeErr);

   /* check call Setup */
   /* check init Public Key | Ephemeral  Public Key */
   IPP_BADARG_RET( NULL == EC_SM2_KEY_EXCH_PUB_KEY_USER_A(pKE)     ||
                   NULL == EC_SM2_KEY_EXCH_PUB_KEY_USER_B(pKE)     ||
                   NULL == EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE) ||
                   NULL == EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE), ippStsContextMatchErr)

   /* check pSPeer */
   IPP_BAD_PTR1_RET(pSPeer);

   /* check status */
   IPP_BAD_PTR1_RET(pStatus);


   const Ipp8u firstNum = (ippKESM2Requester == role) ? 0x02 : 0x03;

   {
      /* extract data Elliptic Curve */
      const int elemBits  = GFP_FEBITLEN(pME);  /* size Bits */
      const int elemBytes = (elemBits + 7) / 8; /* size Bytes */

      /* buffer */
      BNU_CHUNK_T *pDataBuff = cpGFpGetPool(3, pME);
      Ipp8u *pBuff           = (Ipp8u *)pDataBuff;

      /* 8) S(1/2) = SM3( 0x0(2/3) || y(u/v) || tmp_p ) */
      /* copy 0x0(2/3) */
      pBuff[0] = firstNum; /* set first number (role) */
      /* copy y(u/v) */
      cpSM2_CopyBlock(pBuff + 1, (const Ipp8u *)EC_SM2_KEY_EXCH_POINT_Y(pKE), elemBytes);
      /* copy Precomp Hash */
      cpSM2_CopyBlock(pBuff + 1 + elemBytes, (const Ipp8u *)EC_SM2_KEY_EXCH_PRECOM_HASH(pKE), IPP_SM3_DIGEST_BYTESIZE);

      const int sizeSab_SM3 = 1 + elemBytes + IPP_SM3_DIGEST_BYTESIZE;
      cpSM2KE_compute_hash_SM3(pBuff, pBuff, sizeSab_SM3);

      /* pS == S(1/2) */
      *pStatus = EquBlock((Ipp8u *)pBuff, pSPeer, IPP_SM3_DIGEST_BYTESIZE) ? 1 : 0;

      cpGFpReleasePool(3, pME);
      return ippStsNoErr;
   }
}
