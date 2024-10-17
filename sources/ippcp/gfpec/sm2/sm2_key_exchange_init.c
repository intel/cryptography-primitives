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
 * @brief ippsGFpECKeyExchangeSM2_Init
 * initial Key Exchange Context
 * see standard:
 * [GBT.32918.3-2016] Public Key cryptographic algorithm SM2 based on elliptic curves
 * Part 3: Key exchange protocol
 * @param [out] pKE  context Key Exchange
 * @param [in]  role User(A|B) role (ippKESM2Requester|ippKESM2Responder)
 * @param [in]  pEC  context Elliptic Curve
 * @return
 * ippStsNoErr               - successful
 * ippStsNullPtrErr          - if pEC | pKE is NULL
 * ippStsContextMatchErr     - if pEC no valid ID or no exists SUBGROUP
 * ippStsNotSupportedModeErr - if pEC no supported n or p modulus arithmetic
 * ippStsRangeErr            - if BitSize(pEC) < IPP_SM3_DIGEST_BITSIZE
 * ippStsBadArgErr           - if role no equal ippKESM2Requester|ippKESM2Responder
 */
IPPFUN(IppStatus, ippsGFpECKeyExchangeSM2_Init, (IppsGFpECKeyExchangeSM2State * pKE, IppsKeyExchangeRoleSM2 role, IppsGFpECState *pEC))
{
   /* check Elliptic Curve */
   IPP_BAD_PTR1_RET(pEC);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_SUBGROUP(pEC), ippStsContextMatchErr);
   /* check support Mode arithmetic */
   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC)); /* base P */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(pME), ippStsNotSupportedModeErr);
   gsModEngine *nME = ECP_MONT_R(pEC); /* base N */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(nME), ippStsNotSupportedModeErr);
   /* check bitsize >= SM3_DIGSET */
   IPP_BADARG_RET(!(ECP_ORDBITSIZE(pEC) >= IPP_SM3_DIGEST_BITSIZE), ippStsRangeErr);

   /* check Key Exchange */
   IPP_BAD_PTR1_RET(pKE);

   /* check User Role */
   IPP_BADARG_RET(((ippKESM2Requester != role) && (ippKESM2Responder != role)), ippStsBadArgErr);

   {
      const int elemSize = GFP_FELEN(pME); /* size BNU_CHUNK */
      /* set id */
      EC_SM2_KEY_EXCH_SET_ID(pKE);

      /* set role [User A| User B] */
      EC_SM2_KEY_EXCH_ROLE(pKE) = role;

      /* set context EC */
      EC_SM2_KEY_EXCH_EC(pKE) = pEC;

      /* set zero pointer to public key */
      /* public key */
      EC_SM2_KEY_EXCH_PUB_KEY_USER_A(pKE) = NULL;
      EC_SM2_KEY_EXCH_PUB_KEY_USER_B(pKE) = NULL;
      /* ephemera key */
      EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE) = NULL;
      EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE) = NULL;

      Ipp8u *ptr = (Ipp8u *)(pKE);
      ptr += (Ipp32s)sizeof(IppsGFpECKeyExchangeSM2State);

      /* skip Public Key Space */
      ptr += 4 * ((Ipp32s)sizeof(IppsGFpECPoint) + 3 * (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize);

      /* set Za (user id hash) */
      EC_SM2_KEY_EXCH_USER_ID_HASH_USER_A(pKE) = ptr;
      PurgeBlock(ptr, IPP_SM3_DIGEST_BYTESIZE);
      ptr += IPP_SM3_DIGEST_BYTESIZE;

      /* set Zb (user id hash) */
      EC_SM2_KEY_EXCH_USER_ID_HASH_USER_B(pKE) = ptr;
      PurgeBlock(ptr, IPP_SM3_DIGEST_BYTESIZE);
      ptr += IPP_SM3_DIGEST_BYTESIZE;

      /* set Precompute Hash */
      EC_SM2_KEY_EXCH_PRECOM_HASH(pKE) = ptr;
      PurgeBlock(ptr, IPP_SM3_DIGEST_BYTESIZE);
      ptr += IPP_SM3_DIGEST_BYTESIZE;

      /* set Point(X,Y) */
      EC_SM2_KEY_EXCH_POINT_PTR(pKE) = (BNU_CHUNK_T *)ptr;

      ZEXPAND_BNU(EC_SM2_KEY_EXCH_POINT_X(pKE), 0, elemSize);
      ZEXPAND_BNU(EC_SM2_KEY_EXCH_POINT_Y(pKE), 0, elemSize);

      return ippStsNoErr;
   }
}
