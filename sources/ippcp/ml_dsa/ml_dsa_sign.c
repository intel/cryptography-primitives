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
//    Name: ippsMLDSA_Sign
//
// Purpose: Sign the message with private key.
//
// Returns:                    Reason:
//    ippStsNullPtrErr               pPrvKey == NULL
//                                   pMsg == NULL
//                                   pSign == NULL
//                                   pMLDSAState == NULL
//                                   pScratchBuffer == NULL
//                                   pCtx == NULL if ctxLen > 0
//    ippStsContextMatchErr          pMLDSAState is not initialized
//    ippStsMemAllocErr              an internal functional error, see documentation for more details
//    ippStsLengthErr                pMLDSAState was initialized with IPPCP_MLDSA_NO_MESSAGE
//                                   msgLen < 1 or msgLen > IPP_MAX_32S - locSignBytes
//                                   ctxLen < 0 or ctxLen > 255
//    ippStsBadArgErr                ctxLen == 0 if pCtx != NULL
//    ippStsNotSupportedModeErr      unsupported RDRAND instruction
//    ippStsMLDSASignMaxIterations   too many iterations inside the signature generation
//    ippStsErr                      random bit sequence can't be generated
//    A error that may be returned by rndFunc
//    ippStsNoErr                    no errors
//
// Parameters:
//    pMsg           - input pointer to the message data buffer
//    msgLen         - message buffer length
//    pCtx           - input pointer to the context buffer
//    ctxLen         - context buffer length
//    pPrvKey        - input pointer to the private key
//    pSign          - output pointer to the produced signature
//    pMLDSAState    - input pointer to ML DSA context
//    pScratchBuffer - input pointer to the working buffer of size queried ippsMLDSA_SignBufferGetSize()
//    rndFunc        - input function pointer to generate random numbers, can be NULL
//    pRndParam      - input parameters for rndFunc, can be NULL
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsMLDSA_Sign, (const Ipp8u* pMsg,
                                   const Ipp32s msgLen,
                                   const Ipp8u* pCtx,
                                   const Ipp32s ctxLen,
                                   const Ipp8u* pPrvKey,
                                   Ipp8u* pSign,
                                   IppsMLDSAState* pMLDSAState,
                                   Ipp8u* pScratchBuffer,
                                   IppBitSupplier rndFunc,
                                   void* pRndParam))
/* clang-format on */
{
    IppStatus sts = ippStsErr;
    /* Test input parameters */
    IPP_BAD_PTR1_RET(pMsg);
    IPP_BAD_PTR4_RET(pPrvKey, pSign, pMLDSAState, pScratchBuffer);
    IPP_BADARG_RET(msgLen < 1, ippStsLengthErr);
    IPP_BADARG_RET(ctxLen < 0, ippStsLengthErr);
    IPP_BADARG_RET(ctxLen > 255, ippStsLengthErr);
    if (pCtx != NULL) {
        IPP_BADARG_RET(ctxLen == 0, ippStsBadArgErr);
    }
    // check that if ctxLen > 0, pCtx is not NULL
    if (ctxLen > 0) {
        IPP_BAD_PTR1_RET(pCtx);
    }
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_DSA_VALID_ID(pMLDSAState), ippStsContextMatchErr);

    _cpMLDSAParams* params = &(pMLDSAState->params);
    Ipp32s sizeof_polynom  = sizeof(IppPoly);
    Ipp32s locSignBytes    = (2 * params->k + params->l) * sizeof_polynom + 3 * CP_ML_ALIGNMENT;
#if !CP_ML_MEMORY_OPTIMIZATION
    locSignBytes += params->k * params->l * sizeof_polynom + CP_ML_ALIGNMENT;
#endif // !CP_ML_MEMORY_OPTIMIZATION
    locSignBytes += 64 + 2 + 256;
    IPP_BADARG_RET(msgLen > (Ipp32s)(IPP_MAX_32S)-locSignBytes, ippStsLengthErr);

    /* Initialize the temporary storage */
    _cpMLDSAStorage* pStorage = &pMLDSAState->storage;
    IPP_BADARG_RET(pStorage->signCapacity == 0, ippStsLengthErr);

    pStorage->pStorageData  = pScratchBuffer;
    pStorage->bytesCapacity = pStorage->signCapacity;

    __ALIGN32 Ipp8u rnd[CP_RAND_DATA_BYTES] = { 0 };

    /* Random nonce data */
    if (rndFunc == NULL) {
        sts = ippsTRNGenRDSEED((Ipp32u*)rnd, CP_RAND_DATA_BYTES * 8, NULL);
    } else {
        sts = rndFunc((Ipp32u*)rnd, CP_RAND_DATA_BYTES * 8, pRndParam);
    }
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    sts = cp_MLDSA_Sign_internal(pMsg, msgLen, pCtx, ctxLen, pPrvKey, rnd, pSign, pMLDSAState);

    /* Zeroization of sensitive data */
    PurgeBlock(rnd, sizeof(rnd));

    /* Clear temporary storage */
    IppStatus memReleaseSts = cp_mlStorageReleaseAll(pStorage);
    pStorage->pStorageData  = NULL;
    if (memReleaseSts != ippStsNoErr) {
        return memReleaseSts;
    }

    return sts;
}
