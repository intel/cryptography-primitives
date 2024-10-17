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

/**
 * @brief ippsGFpECEncryptSM2_Ext_EncMsgSize
 * Implementation based on standard:
 * GM/T 0003.4-2012 SM2
 * Public key cryptographic algorithm SM2 based on elliptic curves
 * Part 4: Public key encryption algorithm
 * Get Cipher Size data by Encrypt SM2
 * @param [in]  pEC       Context Elliptic Curve
 * @param [in]  ctMsgSize chipher text message size
 * @param [out] pSize     size allocation bytes by Key Exchange Context
 * @return
 * ippStsNoErr           - successful
 * ippStsNullPtrErr      - if pEC or pSize is NULL
 * ippStsContextMatchErr - if pEC no valid ID or no exists SUBGROUP
 * ippStsBagArgErr       - if message size < 0
 */
IPPFUN(IppStatus, ippsGFpECEncryptSM2_Ext_EncMsgSize, (const IppsGFpECState *pEC, int ctMsgSize, int *pSize))
{
   /* check Context Elliptic Curve */
   IPP_BAD_PTR2_RET(pEC, pSize);
   IPP_BADARG_RET(!VALID_ECP_ID(pEC), ippStsContextMatchErr);
   IPP_BADARG_RET(!ECP_SUBGROUP(pEC), ippStsContextMatchErr);

   gsModEngine *pME = GFP_PMA(ECP_GFP(pEC)); /* base P */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(pME), ippStsNotSupportedModeErr);
   gsModEngine *nME = ECP_MONT_R(pEC); /* base N */
   IPP_BADARG_RET(1 < GFP_EXTDEGREE(nME), ippStsNotSupportedModeErr);

   const int elemSize = GFP_FELEN(pME); /* size BNU_CHUNK */

   /* check message size */
   IPP_BADARG_RET(!(ctMsgSize >= 0), ippStsOutOfRangeErr)

   {
      const int ciph_PC_size   = 1;
      const int ciph_xy_size   = 2 * (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize;
      const int ciph_hash_size = IPP_SM3_DIGEST_BYTESIZE;
      const int ciph_msg_size  = ctMsgSize;

      const int size = ciph_PC_size     /* PC */
                       + ciph_xy_size   /* Point (x,y) */
                       + ciph_hash_size /* SM3 */
                       + ciph_msg_size; /* message size */

      *pSize = size;
      return ippStsNoErr;
   }
}
