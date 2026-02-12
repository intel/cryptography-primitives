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

#include "owndefs.h"
#include "owncp.h"
#include "pcptool.h"
#include "drbg/pcphashdrbg.h"
#include "drbg/pcphashdrbg_entropy_input.h"

/*
//    Name: ippsHashDRBG_EntropyInputCtxInit
//
// Purpose: Initializes IppsHashDRBG_EntropyInputCtx
//
// Returns:                     Reason:
//    ippStsNullPtrErr           pEntrInputCtx == NULL
//    ippStsOutOfRangeErr        entrInputBufBitsLen exceeds max value or is 0
//    ippStsNoErr                No errors
//
// Parameters:
//    pEntrInputCtx        Pointer to the Entropy input context
//    entrInputBufBitsLen  The length of the entropy input in bits
//    getEntropyInput      Callback function
*/

IPPFUN(IppStatus,
       ippsHashDRBG_EntropyInputCtxInit,
       (IppsHashDRBG_EntropyInputCtx * pEntrInputCtx,
        const int entrInputBufBitsLen,
        IppEntropyInputSupplier getEntropyInput))
{
    IPP_BAD_PTR1_RET(pEntrInputCtx);

    /* entrInputBufBitsLen < 1
       1) if entropyInput length exceeds max value, an integer overflow occurs
          that results to a change of the sign
       2) entrInputBufBitsLen cannot be zero */
    IPP_BADARG_RET(entrInputBufBitsLen < 1, ippStsOutOfRangeErr);

    {
        /* zeroize Entropy input context */
        PurgeBlock((void*)pEntrInputCtx,
                   (int)sizeof(IppsHashDRBG_EntropyInputCtx) +
                       BITS2WORD8_SIZE(entrInputBufBitsLen));

        HASH_DRBG_ENTR_INPUT_SET_ID(pEntrInputCtx);

        pEntrInputCtx->entrInputBufBitsLen = entrInputBufBitsLen;
        pEntrInputCtx->getEntropyInput     = getEntropyInput;

        Ipp8u* pTempCtx = (Ipp8u*)pEntrInputCtx;
        pTempCtx += sizeof(IppsHashDRBG_EntropyInputCtx);
        pEntrInputCtx->entropyInput = (Ipp8u*)pTempCtx;
    }

    return ippStsNoErr;
}
