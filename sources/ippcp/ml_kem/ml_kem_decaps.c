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

#include "owncp.h"
#include "owndefs.h"

#include "pcptool.h"
#include "stateless_pqc/ml_kem_internal/ml_kem.h"

/*F*
//    Name: ippsMLKEM_Decaps
//
// Purpose: Uses the decapsulation key to produce a shared secret key from a ciphertext.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pDecKey == NULL
//                            pCipherText == NULL
//                            pSharedSecret == NULL
//                            pMLKEMCtx == NULL
//                            pScratchBuffer == NULL
//    ippStsContextMatchErr   pMLKEMCtx is not initialized
//    ippStsMemAllocErr       an internal functional error, see documentation for more details
//    ippStsOutOfRangeErr     an internal functional error, see documentation for more details
//    ippStsNoErr             no errors
//
// Parameters:
//    pDecKey        - input pointer to decapsulation key of size 786*k + 96 bytes
//    pCipherText    - input pointer to the ciphertext of length 32*(d_{u}*k + d_{v})) bytes
//    pSharedSecret  - output pointer to the produced shared secret of length 32 bytes
//    pMLKEMCtx      - input pointer to ML KEM context
//    pScratchBuffer - input pointer to the working buffer of size queried ippsMLKEM_DecapsBufferGetSize()
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsMLKEM_Decaps, (const Ipp8u* pDecKey,
                                     const Ipp8u* pCipherText,
                                     Ipp8u* pSharedSecret,
                                     IppsMLKEMState* pMLKEMCtx,
                                     Ipp8u* pScratchBuffer))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;

    /* Test input pointers */
    IPP_BAD_PTR4_RET(pDecKey, pCipherText, pSharedSecret, pMLKEMCtx);
    IPP_BAD_PTR1_RET(pScratchBuffer);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_KEM_VALID_ID(pMLKEMCtx), ippStsContextMatchErr);

    /* Initialize the temporary storage */
    _cpMLKEMStorage* pStorage = &pMLKEMCtx->storage;
    pStorage->pStorageData    = pScratchBuffer;
    pStorage->bytesCapacity   = pStorage->decapsCapacity;

    sts = cp_MLKEMdecaps_internal(pSharedSecret, pCipherText, pDecKey, pMLKEMCtx);

    /* Clear temporary storage */
    IppStatus memReleaseSts = cp_mlStorageReleaseAll(pStorage);
    pStorage->pStorageData  = NULL;
    if (memReleaseSts != ippStsNoErr) {
        return memReleaseSts;
    }

    return sts;
}
