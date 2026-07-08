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
//    Name: ippsMLKEM_Encaps
//
// Purpose: Uses the encapsulation key to generate a shared secret key and an associated ciphertext.
//
// Returns:                Reason:
//    ippStsNullPtrErr           pEncKey == NULL
//                               pCipherText == NULL
//                               pSharedSecret == NULL
//                               pMLKEMCtx == NULL
//                               pScratchBuffer == NULL
//    ippStsContextMatchErr      pMLKEMCtx is not initialized
//    ippStsMemAllocErr          an internal functional error, see documentation for more details
//    ippStsNotSupportedModeErr  unsupported RDRAND instruction
//    ippStsErr                  random bit sequence can't be generated
//    An error that may be returned by rndFunc
//    ippStsNoErr             no errors
//
// Parameters:
//    pEncKey        - input pointer to encapsulation key of size 384*k + 32 bytes
//    pCipherText    - output pointer to the produced ciphertext of length 32*(d_{u}*k + d_{v})) bytes
//    pSharedSecret  - output pointer to the produced shared secret of length 32 bytes
//    pMLKEMCtx      - input pointer to ML KEM context
//    pScratchBuffer - input pointer to the working buffer of size queried ippsMLKEM_EncapsBufferGetSize()
//    rndFunc        - input function pointer to generate random numbers, can be NULL
//    pRndParam      - input parameters for rndFunc, can be NULL
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsMLKEM_Encaps, (const Ipp8u* pEncKey,
                                     Ipp8u* pCipherText,
                                     Ipp8u* pSharedSecret,
                                     IppsMLKEMState* pMLKEMCtx,
                                     Ipp8u* pScratchBuffer,
                                     IppBitSupplier rndFunc,
                                     void* pRndParam))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;

    /* Test input pointers */
    IPP_BAD_PTR4_RET(pCipherText, pSharedSecret, pEncKey, pMLKEMCtx);
    IPP_BAD_PTR1_RET(pScratchBuffer);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_KEM_VALID_ID(pMLKEMCtx), ippStsContextMatchErr);

    /* Initialize the temporary storage */
    _cpMLKEMStorage* pStorage = &pMLKEMCtx->storage;
    pStorage->pStorageData    = IPP_ALIGNED_PTR(pScratchBuffer, CP_ML_KEM_ALIGNMENT);
    pStorage->bytesCapacity   = pStorage->encapsCapacity;

    /* m <-- 32 random bytes */
    __ALIGN32 Ipp8u m[CP_RAND_DATA_BYTES];

    /* Random nonce data */
    if (rndFunc == NULL) {
        sts = ippsPRNGenRDRAND((Ipp32u*)m, CP_RAND_DATA_BYTES * 8, NULL);
    } else {
        sts = rndFunc((Ipp32u*)m, CP_RAND_DATA_BYTES * 8, pRndParam);
    }
    if (sts != ippStsNoErr) {
        PurgeBlock(m, sizeof(m));
        return sts;
    }

    sts = cp_MLKEMencaps_internal(pSharedSecret, pCipherText, pEncKey, m, pMLKEMCtx);

    /* Zeroization of sensitive data */
    PurgeBlock(m, sizeof(m));

    /* Clear temporary storage */
    IppStatus memReleaseSts = cp_mlStorageReleaseAll(pStorage);
    pStorage->pStorageData  = NULL;
    if (memReleaseSts != ippStsNoErr) {
        return memReleaseSts;
    }

    return sts;
}
