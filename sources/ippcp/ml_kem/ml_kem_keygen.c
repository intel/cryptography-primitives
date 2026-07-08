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
//    Name: ippsMLKEM_KeyGen
//
// Purpose: Generates an encapsulation key and a corresponding decapsulation key.
//
// Returns:                Reason:
//    ippStsNullPtrErr           pEncKey == NULL
//                               pDecKey == NULL
//                               pMLKEMCtx == NULL
//                               pScratchBuffer == NULL
//    ippStsContextMatchErr      pMLKEMCtx is not initialized
//    ippStsMemAllocErr          an internal functional error, see documentation for more details
//    ippStsNotSupportedModeErr  unsupported RDRAND instruction
//    ippStsErr                  random bit sequence can't be generated
//    A error that may be returned by rndFunc
//    ippStsNoErr                no errors
//
// Parameters:
//    pEncKey        - output pointer to the produced encapsulation key of length 384*k + 32 bytes
//    pDecKey        - output pointer to the produced decapsulation key of length 786*k + 96 bytes
//    pMLKEMCtx      - input pointer to ML KEM context
//    pScratchBuffer - input pointer to the working buffer of size queried ippsMLKEM_KeyGenBufferGetSize()
//    rndFunc        - input function pointer to generate random numbers, can be NULL
//    pRndParam      - input parameters for rndFunc, can be NULL
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsMLKEM_KeyGen, (Ipp8u * pEncKey,
                                     Ipp8u* pDecKey,
                                     IppsMLKEMState* pMLKEMCtx,
                                     Ipp8u* pScratchBuffer,
                                     IppBitSupplier rndFunc,
                                     void* pRndParam))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;

    /* Test input parameters */
    IPP_BAD_PTR4_RET(pMLKEMCtx, pEncKey, pDecKey, pScratchBuffer);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_KEM_VALID_ID(pMLKEMCtx), ippStsContextMatchErr);

    /* Initialize the temporary storage */
    _cpMLKEMStorage* pStorage = &pMLKEMCtx->storage;
    pStorage->pStorageData    = pScratchBuffer;
    pStorage->bytesCapacity   = pStorage->keyGenCapacity;

    /* d, z <-- 32 random bytes + 1 byte in d for k */
    __ALIGN32 Ipp8u d_k[CP_RAND_DATA_BYTES + 1];
    __ALIGN32 Ipp8u z[CP_RAND_DATA_BYTES];

    /* Random nonce data */
    if (rndFunc == NULL) {
        sts = ippsPRNGenRDRAND((Ipp32u*)d_k, CP_RAND_DATA_BYTES * 8, NULL);
        sts |= ippsPRNGenRDRAND((Ipp32u*)z, CP_RAND_DATA_BYTES * 8, NULL);
    } else {
        sts = rndFunc((Ipp32u*)d_k, CP_RAND_DATA_BYTES * 8, pRndParam);
        sts |= rndFunc((Ipp32u*)z, CP_RAND_DATA_BYTES * 8, pRndParam);
    }
    if (sts != ippStsNoErr) {
        PurgeBlock(d_k, sizeof(d_k));
        PurgeBlock(z, sizeof(z));
        return sts;
    }
    /* 32nd byte equals to k */
    d_k[CP_RAND_DATA_BYTES] = pMLKEMCtx->params.k;

    /* (ek,dk) <- ML-KEM.KeyGen_internal(d,z) */
    sts = cp_MLKEMkeyGen_internal(pEncKey, pDecKey, d_k, z, pMLKEMCtx);

    /* Zeroization of sensitive data */
    PurgeBlock(d_k, sizeof(d_k));
    PurgeBlock(z, sizeof(z));

    /* Clear temporary storage */
    IppStatus memReleaseSts = cp_mlStorageReleaseAll(pStorage);
    pStorage->pStorageData  = NULL;
    if (memReleaseSts != ippStsNoErr) {
        return memReleaseSts;
    }

    return sts;
}
