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

#include "stateless_pqc/ml_dsa/ml_dsa.h"

/*F*
//    Name: ippsMLDSA_KeyGen
//
// Purpose: Generates public and private keys.
//
// Returns:                Reason:
//    ippStsNullPtrErr           pPubKey == NULL
//                               pPrvKey == NULL
//                               pMLDSAState == NULL
//                               pScratchBuffer == NULL
//    ippStsContextMatchErr      pMLDSAState is not initialized
//    ippStsMemAllocErr          an internal functional error, see documentation for more details
//    ippStsNotSupportedModeErr  unsupported RDRAND instruction
//    ippStsErr                  random bit sequence can't be generated
//    A error that may be returned by rndFunc
//    ippStsNoErr                no errors
//
// Parameters:
//    pPubKey        - output pointer to the produced public key
//    pPrvKey        - output pointer to the produced private key
//    pMLDSAState    - input pointer to ML DSA state
//    pScratchBuffer - input pointer to the working buffer of size queried ippsMLDSA_KeyGenBufferGetSize()
//    rndFunc        - input function pointer to generate random numbers, can be NULL
//    pRndParam      - input parameters for rndFunc, can be NULL
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsMLDSA_KeyGen, (Ipp8u* pPubKey,
                                     Ipp8u* pPrvKey,
                                     IppsMLDSAState* pMLDSAState,
                                     Ipp8u* pScratchBuffer,
                                     IppBitSupplier rndFunc,
                                     void* pRndParam))
/* clang-format on */
{
    IppStatus sts = ippStsErr;

    /* Test input parameters */
    IPP_BAD_PTR4_RET(pMLDSAState, pPubKey, pPrvKey, pScratchBuffer);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_DSA_VALID_ID(pMLDSAState), ippStsContextMatchErr);

    /* Initialize the temporary storage */
    _cpMLDSAStorage* pStorage = &pMLDSAState->storage;
    pStorage->pStorageData    = pScratchBuffer;
    pStorage->bytesCapacity   = pStorage->keyGenCapacity;

    /* Random nonce data */
    __ALIGN32 Ipp8u ksi[CP_RAND_DATA_BYTES] = { 0 };
    if (rndFunc == NULL) {
        sts = ippsTRNGenRDSEED((Ipp32u*)ksi, CP_RAND_DATA_BYTES * 8, NULL);
    } else {
        sts = rndFunc((Ipp32u*)ksi, CP_RAND_DATA_BYTES * 8, pRndParam);
    }
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    sts = cp_MLDSA_keyGen_internal(ksi, pPubKey, pPrvKey, pMLDSAState);

    /* Zeroization of sensitive data */
    PurgeBlock(ksi, sizeof(ksi));

    /* Clear temporary storage */
    IppStatus memReleaseSts = cp_mlStorageReleaseAll(pStorage);
    pStorage->pStorageData  = NULL;
    if (memReleaseSts != ippStsNoErr) {
        return memReleaseSts;
    }

    return sts;
}
