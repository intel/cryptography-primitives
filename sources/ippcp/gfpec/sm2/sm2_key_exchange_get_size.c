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
 * @brief ippsGFpECKeyExchangeSM2_GetSize
 * Get Size allocation bytes by Key Exchange Conntext
 * @param [in]  pEC   Context Elliptic Curve
 * @param [out] pSize size allocation bytes by Key Exchange Context
 * @return
 * ippStsNoErr           - successful
 * ippStsNullPtrErr      - if pEC or pSize is NULL
 * ippStsContextMatchErr - if pEC no valid ID or no exists SUBGROUP
 */
IPPFUN(IppStatus, ippsGFpECKeyExchangeSM2_GetSize, (const IppsGFpECState *pEC, int *pSize))
{

   IPP_BAD_PTR2_RET(pEC, pSize);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_SUBGROUP(pEC), ippStsContextMatchErr);

   {
      gsModEngine *pME   = GFP_PMA(ECP_GFP(pEC)); /* base P */
      const int elemSize = GFP_FELEN(pME);        /* size BNU_CHUNK */

      const int size = (Ipp32s)sizeof(IppsGFpECKeyExchangeSM2State)                                  /* Key Exchange SM2 struct */
                       + (Ipp32s)sizeof(IppsGFpECPoint) + 3 * (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize /* User A Public Key + Data */
                       + (Ipp32s)sizeof(IppsGFpECPoint) + 3 * (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize /* User B Public Key + Data */
                       + (Ipp32s)sizeof(IppsGFpECPoint) + 3 * (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize /* User A Ephemeral Public Key + Data */
                       + (Ipp32s)sizeof(IppsGFpECPoint) + 3 * (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize /* User B Ephemeral Public Key + Data */
                       + (Ipp32s)sizeof(Ipp8u) * IPP_SM3_DIGEST_BYTESIZE                             /* Za [User A] */
                       + (Ipp32s)sizeof(Ipp8u) * IPP_SM3_DIGEST_BYTESIZE                             /* Zb [User B] */
                       + (Ipp32s)sizeof(Ipp8u) * IPP_SM3_DIGEST_BYTESIZE                             /*  Precompute Hash */
                       + (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize                                      /* [U/V].x */
                       + (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize;                                     /* [U/V].y */

      *pSize = size;
      return ippStsNoErr;
   }
}