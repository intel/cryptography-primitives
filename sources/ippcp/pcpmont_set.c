/*************************************************************************
* Copyright (C) 2002 Intel Corporation
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

/*
//               Intel(R) Cryptography Primitives Library
//
//  Contents:
//        cpMontSet()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpbn.h"
#include "pcpmontgomery.h"
#include "pcptool.h"


/* Auxilirary function */
__IPPCP_INLINE int cpGetBitSize(Ipp32u offset, Ipp32u val)
{
    int bitSize = 31;
    if (val == 0) return 0;
    while ((val & (1 << bitSize)) == 0) bitSize--;
    return (int)offset + bitSize;
}

/*F*
// Name: cpMontSet
//
// Purpose: Setup modulus value
//
// Returns:                   Reason:
//    ippStsBadModulusErr        (pModulus[0] & 1) == 0
//    ippStsOutOfRangeErr        ((Ipp32u)MNT_ROOM(pMont) < INTERNAL_BNU_LENGTH(len32))
//    ippStsLengthErr            len32<1
//    ippStsNoErr                no errors
//
// Parameters:
//    pModulus    pointer to the modulus buffer
//    len32       length of the  modulus (in Ipp32u chunks).
//    pMont       pointer to the context
*F*/

IPP_OWN_DEFN (IppStatus, cpMontSet, (const Ipp32u* pModulus, cpSize len32, IppsMontState* pMont))
{
   IPP_BADARG_RET(len32<1, ippStsLengthErr);

   /* modulus is not an odd number */
   IPP_BADARG_RET((pModulus[0] & 1) == 0, ippStsBadModulusErr);
   IPP_BADARG_RET(MNT_ROOM(pMont)<(int)(INTERNAL_BNU_LENGTH(len32)), ippStsOutOfRangeErr);

   {
      const int poolLen  = MOD_MAXPOOL(MNT_ENGINE(pMont));
      int modulusBitSize = cpGetBitSize((Ipp32u)((len32 - 1) << 5), pModulus[len32-1]);

      gsModEngineInit(MNT_ENGINE(pMont), pModulus, modulusBitSize, poolLen, gsModArithMont());

      return ippStsNoErr;
   }
}
