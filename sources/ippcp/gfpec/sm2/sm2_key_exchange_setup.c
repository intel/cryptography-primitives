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
#include "gfpec/pcpgfpecstuff.h"
#include "gfpec/sm2/sm2_key_exchange_method.h"
#include "gfpec/sm2/sm2_stuff.h"

#define CHECK_PUBLIC_KEY(KEY)                                                    \
   IPP_BAD_PTR1_RET((KEY))                                                       \
   IPP_BADARG_RET(!ECP_POINT_VALID_ID((KEY)), ippStsContextMatchErr)             \
   IPP_BADARG_RET(ECP_POINT_FELEN((KEY)) != GFP_FELEN(pME), ippStsOutOfRangeErr) \
   IPP_BADARG_RET(0 == gfec_IsPointOnCurve((KEY), pEC), ippStsInvalidPoint)


/**
 * @brief ippsGFpECKeyExchangeSM2_Setup
 * setup Key Exchange Context (add Za | Zb | Pa | Pb | Ra | Rb)
 * see standard:
 * [GBT.32918.3-2016] Public Key cryptographic algorithm SM2 based on elliptic curves
 * Part 3: Key exchange protocol
 * @param [in]  pZSelf            (self) user ID hash Z       (copy)
 * @param [in]  pZPeer            (peer) user ID hash Z       (copy)
 * @param [in]  pPublicKeySelf    (self) public key           (copy)
 * @param [in]  pPublicKeyPeer    (peer) public key           (copy)
 * @param [in]  pEphPublicKeySelf (self) ephemeral public key (copy)
 * @param [in]  pEphPublicKeyPeer (peer) ephemeral public key (copy)
 * @param [out] pKE               context
 * @return
 * ippStsNoErr               - successful
 * ippStsNullPtrErr          - if pEC | pKE is NULL
 * ippStsContextMatchErr     - if pEC no valid ID | pEC no exists SUBGROUP
 * ippStsNotSupportedModeErr - if pEC no supported (n|p) modulus arithmetic
 * ippStsRangeErr            - if BitSize(pEC) < IPP_SM3_DIGEST_BITSIZE
 * ippStsBadArgErr           - if role(pKE) no equal ippKESM2Requester|ippKESM2Responder
 * ippStsInvalidPoint        - if no in curve Pub Key (User A|B) | Eph Pub Key (User A|B)
 */
/* clang-format off */
IPPFUN(IppStatus, ippsGFpECKeyExchangeSM2_Setup, (const Ipp8u pZSelf[IPP_SM3_DIGEST_BYTESIZE],
                                                  const Ipp8u pZPeer[IPP_SM3_DIGEST_BYTESIZE],
                                                  const IppsGFpECPoint *pPublicKeySelf,
                                                  const IppsGFpECPoint *pPublicKeyPeer,
                                                  const IppsGFpECPoint *pEphPublicKeySelf,
                                                  const IppsGFpECPoint *pEphPublicKeyPeer,
                                                  IppsGFpECKeyExchangeSM2State *pKE))
/* clang-format on */
{
   /* check Key Exchange */
   IPP_BAD_PTR1_RET(pKE);
   /* check id */
   IPP_BADARG_RET(!EC_SM2_KEY_EXCH_VALID_ID(pKE), ippStsContextMatchErr);
   /* check User Role */
   const IppsKeyExchangeRoleSM2 role = EC_SM2_KEY_EXCH_ROLE(pKE);
   IPP_BADARG_RET(((ippKESM2Requester != role) && (ippKESM2Responder != role)), ippStsBadArgErr);

   /* check Za | Zb */
   IPP_BAD_PTR2_RET(pZSelf, pZPeer);

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

   /* check data User A */
   /* public and ephemeral public key */
   CHECK_PUBLIC_KEY(pPublicKeySelf)
   CHECK_PUBLIC_KEY(pEphPublicKeySelf)

   /* check data User B */
   /* public and ephemeral public key */
   CHECK_PUBLIC_KEY(pPublicKeyPeer)
   CHECK_PUBLIC_KEY(pEphPublicKeyPeer)

   {
      const int elemSize = GFP_FELEN(pME); /* size BNU_CHUNK */

      /* init pointer copy User A|B */
      Ipp8u *pCopyZSelf = (ippKESM2Requester == role) ? EC_SM2_KEY_EXCH_USER_ID_HASH_USER_A(pKE) : EC_SM2_KEY_EXCH_USER_ID_HASH_USER_B(pKE);
      Ipp8u *pCopyZPeer = (ippKESM2Requester == role) ? EC_SM2_KEY_EXCH_USER_ID_HASH_USER_B(pKE) : EC_SM2_KEY_EXCH_USER_ID_HASH_USER_A(pKE);
      /* copy Za and Zb */
      cpSM2_CopyBlock(pCopyZSelf, pZSelf, IPP_SM3_DIGEST_BYTESIZE);
      cpSM2_CopyBlock(pCopyZPeer, pZPeer, IPP_SM3_DIGEST_BYTESIZE);

      /* init ptr pointer */
      /* User A */
      const IppsGFpECPoint *loc_pub_key_user_a     = (ippKESM2Requester == role) ? pPublicKeySelf : pPublicKeyPeer;
      const IppsGFpECPoint *loc_eph_pub_key_user_a = (ippKESM2Requester == role) ? pEphPublicKeySelf : pEphPublicKeyPeer;
      /* User B */
      const IppsGFpECPoint *loc_pub_key_user_b     = (ippKESM2Requester == role) ? pPublicKeyPeer : pPublicKeySelf;
      const IppsGFpECPoint *loc_eph_pub_key_user_b = (ippKESM2Requester == role) ? pEphPublicKeyPeer : pEphPublicKeySelf;
      /* Copy Pointer User A|B */
      const Ipp32s size_struct_point = (Ipp32s)sizeof(IppsGFpECPoint);
      const Ipp32s size_data_point   = 3 * (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize;

      Ipp8u *ptr = (Ipp8u *)(pKE) + sizeof(IppsGFpECKeyExchangeSM2State);

      /* Public key User A */
      EC_SM2_KEY_EXCH_PUB_KEY_USER_A(pKE) = (IppsGFpECPoint *)ptr;
      ptr += size_struct_point;
      cpSM2KE_CopyPointData(EC_SM2_KEY_EXCH_PUB_KEY_USER_A(pKE), (BNU_CHUNK_T *)ptr, loc_pub_key_user_a, pEC);
      ptr += size_data_point;
      /* Ephemeral Public Key User A */
      EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE) = (IppsGFpECPoint *)ptr;
      ptr += size_struct_point;
      cpSM2KE_CopyPointData(EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_A(pKE), (BNU_CHUNK_T *)ptr, loc_eph_pub_key_user_a, pEC);
      ptr += size_data_point;
      /* Public key User B */
      EC_SM2_KEY_EXCH_PUB_KEY_USER_B(pKE) = (IppsGFpECPoint *)ptr;
      ptr += size_struct_point;
      cpSM2KE_CopyPointData(EC_SM2_KEY_EXCH_PUB_KEY_USER_B(pKE), (BNU_CHUNK_T *)ptr, loc_pub_key_user_b, pEC);
      ptr += size_data_point;
      /* Ephemeral Public Key User B */
      EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE) = (IppsGFpECPoint *)ptr;
      ptr += size_struct_point;
      cpSM2KE_CopyPointData(EC_SM2_KEY_EXCH_EPH_PUB_KEY_USER_B(pKE), (BNU_CHUNK_T *)ptr, loc_eph_pub_key_user_b, pEC);

      return ippStsNoErr;
   }
}

#undef CHECK_PUBLIC_KEY
