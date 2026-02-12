/*************************************************************************
* Copyright (C) 2026 Intel Corporation
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

#include "pcptool.h"
#include "drbg/pcphashdrbg.h"
#include "hash/pcphash.h"

/*
//    Name: ippsHashDRBG_Uninstantiate
//
// Purpose: Uninstatiate DRBG
//
// Returns:                Reason:
//    ippStsNullPtrErr        pDrbgCtx == NULL
//    ippStsContextMatchErr   If the Hash DRBG identifier doesn't match
//    ippStsNoErr             No errors
//
// Parameters:
//    pDrbgCtx             Pointer to the DRBG state
//
// NIST.SP.800-90Ar1 Section 9.4 "Removing a DRBG Instantiation"
*/

IPPFUN(IppStatus, ippsHashDRBG_Uninstantiate, (IppsHashDRBGState * pDrbgCtx))
{
    IPP_BAD_PTR1_RET(pDrbgCtx);
    IPP_BADARG_RET(!HASH_DRBG_VALID_ID(pDrbgCtx), ippStsContextMatchErr);

    int size;
    IppStatus sts = ippsHashDRBG_GetSize(&size, pDrbgCtx->pHashMethod);
    if (ippStsNoErr != sts) {
        return sts;
    }
    PurgeBlock((void*)pDrbgCtx, size);

    return ippStsNoErr;
}
