/*************************************************************************
* Copyright (C) 2025 Intel Corporation
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
//
//  Purpose:
//     Cryptography Primitive.
//     Security Hash Standard
//     Generalized Functionality
//
//  Contents:
//        ippsHashSqueeze_rmf()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"

/*F*
// Name: ippsHashSqueeze_rmf
//
// Purpose: Calculates the rest of hash if any and puts it to user's buffer
//
// Returns:                   Reason:
//    ippStsNullPtrErr           pState == NULL
//                               pMD == NULL
//    ippStsContextMatchErr      pState->idCtx != idCtxHash
//                               HashSqueeze != HASH_STATE(pState) && HASH_SQUEEZED(pState) != 0
//    ippStsNotSupportedModeErr  not supported method
//    ippStsOutOfRangeErr        digestLen <= 0
//    ippStsNoErr                no errors
//
// Parameters:
//    pMD                address of the output digest
//    pState             pointer to the hash context
//    digestLen          length of the hash to be squeezed
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsHashSqueeze_rmf, (Ipp8u * pMD,
                                        const int digestLen,
                                        IppsHashState_rmf* pState))
/* clang-format on */
{
    /* test state pointer and ID */
    IPP_BAD_PTR2_RET(pMD, pState);
    IPP_BADARG_RET(!HASH_VALID_ID(pState, idCtxHash), ippStsContextMatchErr);

    /* SHAKE128/256 are only supported */
    IPP_BADARG_RET(!cpIsSHAKEAlgID(HASH_METHOD(pState)->hashAlgId), ippStsNotSupportedModeErr);

    IPP_BADARG_RET(digestLen <= 0, ippStsOutOfRangeErr);

    if ((HashSqueeze != HASH_STATE(pState)) && (HASH_SQUEEZED(pState) == 0)) {
        cpFinalize_rmf(HASH_VALUE(pState),
                       HASH_BUFF(pState),
                       HASH_BUFFIDX(pState),
                       HASH_LENLO(pState),
                       HASH_LENHI(pState),
                       HASH_METHOD(pState));
    } else if ((HashSqueeze != HASH_STATE(pState)) && (HASH_SQUEEZED(pState) != 0))
        return ippStsContextMatchErr;

    cpHashSqueeze(pMD, HASH_VALUE(pState), HASH_METHOD(pState), digestLen, &HASH_SQUEEZED(pState));

    HASH_STATE(pState) = HashSqueeze;

    return ippStsNoErr;
}
