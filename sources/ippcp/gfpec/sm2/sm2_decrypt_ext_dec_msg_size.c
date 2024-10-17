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
 * @brief ippsGFpECDecryptSM2_Ext_DecMsgSize
 * Get Message Size data by Decrypt SM2
 * Implementation based on standard:
 * GM/T 0003.4-2012 SM2
 * Public key cryptographic algorithm SM2 based on elliptic curves
 * Part 4: Public key encryption algorithm
 * @param [in]  pEC       Context Elliptic Curve
 * @param [in]  ctMsgSize cipher size
 * @param [out] pSize     size allocation bytes by Key Exchange Context
 * @return
 * ippStsNoErr           - successful
 * ippStsNullPtrErr      - if pEC or pSize is NULL
 * ippStsContextMatchErr - if pEC no valid ID or no exists SUBGROUP
 * ippStsBagArgErr       - if cipher < 0 or ctMsgSize - (C1 + C3) < 0
 */
IPPFUN(IppStatus, ippsGFpECDecryptSM2_Ext_DecMsgSize, (const IppsGFpECState *pEC, int ctMsgSize, int *pSize))
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

   /* check cipher size */
   IPP_BADARG_RET(!(ctMsgSize >= 0), ippStsOutOfRangeErr)
   const int ciph_PC_size   = 1;
   const int ciph_xy_size   = 2 * (Ipp32s)sizeof(BNU_CHUNK_T) * elemSize;
   const int ciph_hash_size = IPP_SM3_DIGEST_BYTESIZE;

   const int size = ctMsgSize - (ciph_PC_size + ciph_xy_size + ciph_hash_size);

   /* if size < 0 -> pSize = 0 + call ippStsBadArgErr */
   *pSize = 0;
   IPP_BADARG_RET(!(size >= 0), ippStsOutOfRangeErr)

   *pSize = size;
   return ippStsNoErr;
}
