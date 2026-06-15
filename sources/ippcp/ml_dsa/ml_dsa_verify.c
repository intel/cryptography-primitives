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
//    Name: ippsMLDSA_Verify
//
// Purpose: Verify the message with public key.
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMsg == NULL
//                               pPubKey == NULL
//                               pSign == NULL
//                               pIsSignValid == NULL
//                               pMLDSAState == NULL
//                               pScratchBuffer == NULL
//                               pCtx == NULL if ctxLen > 0
//    ippStsContextMatchErr      pMLDSAState is not initialized
//    ippStsMemAllocErr          an internal functional error, see documentation for more details
//    ippStsLengthErr            pMLDSAState was initialized with IPPCP_MLDSA_NO_MESSAGE
//                               msgLen < 1 or msgLen > IPP_MAX_32S - locVerifyBytes
//                               ctxLen < 0 or ctxLen > 255
//    ippStsBadArgErr            ctxLen == 0 if pCtx != NULL
//    ippStsNoErr                no errors
//
// Parameters:
//    pMsg           - input pointer to the message data buffer
//    msgLen         - message buffer length
//    pCtx           - input pointer to the context buffer
//    ctxLen         - context buffer length
//    pPubKey        - input pointer to the public key
//    pSign          - input pointer to the signature
//    pIsSignValid   - output pointer to the verification result (1 - valid, 0 - invalid)
//    pMLDSAState    - input pointer to ML DSA context
//    pScratchBuffer - input pointer to the working buffer of size queried ippsMLDSA_SignBufferGetSize()
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsMLDSA_Verify, (const Ipp8u* pMsg,
                                     const Ipp32s msgLen,
                                     const Ipp8u* pCtx,
                                     const Ipp32s ctxLen,
                                     const Ipp8u* pPubKey,
                                     const Ipp8u* pSign,
                                     int* pIsSignValid,
                                     IppsMLDSAState* pMLDSAState,
                                     Ipp8u* pScratchBuffer))
/* clang-format on */
{
    IppStatus sts = ippStsErr;
    /* Test input parameters */
    IPP_BAD_PTR3_RET(pMsg, pIsSignValid, pPubKey);
    IPP_BAD_PTR3_RET(pSign, pMLDSAState, pScratchBuffer);
    *pIsSignValid = 0;
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

    Ipp32s locVerifyBytes = 0;
    Ipp32s sizeof_polynom = sizeof(IppPoly);
    locVerifyBytes = 3 * pMLDSAState->params.k * sizeof_polynom + pMLDSAState->params.lambda_div_4 +
                     4 * CP_ML_ALIGNMENT;
#if !CP_ML_MEMORY_OPTIMIZATION
    locVerifyBytes +=
        pMLDSAState->params.k * pMLDSAState->params.l * sizeof_polynom + CP_ML_ALIGNMENT;
#endif // !CP_ML_MEMORY_OPTIMIZATION
    locVerifyBytes += 64 + 2 + 256 + CP_ML_ALIGNMENT;
    IPP_BADARG_RET(msgLen > (Ipp32s)(IPP_MAX_32S)-locVerifyBytes, ippStsLengthErr);

    /* Initialize the temporary storage */
    _cpMLDSAStorage* pStorage = &pMLDSAState->storage;
    IPP_BADARG_RET(pStorage->verifyCapacity == 0, ippStsLengthErr);

    pStorage->pStorageData  = pScratchBuffer;
    pStorage->bytesCapacity = pStorage->verifyCapacity;

    sts = cp_MLDSA_Verify_internal(pMsg,
                                   msgLen,
                                   pCtx,
                                   ctxLen,
                                   pPubKey,
                                   pSign,
                                   pIsSignValid,
                                   pMLDSAState);

    /* Clear temporary storage */
    IppStatus memReleaseSts = cp_mlStorageReleaseAll(pStorage);
    pStorage->pStorageData  = NULL;
    if (memReleaseSts != ippStsNoErr) {
        return memReleaseSts;
    }

    return sts;
}

/*F*
//    Name: ippsMLDSA_Verify_Mu
//
// Purpose: Verify the signature using pre-computed Mu hash value.
//
// Returns:                Reason:
//    ippStsNullPtrErr           pMu == NULL
//                               pPubKey == NULL
//                               pSign == NULL
//                               pIsSignValid == NULL
//                               pMLDSAState == NULL
//                               pScratchBuffer == NULL
//    ippStsContextMatchErr      pMLDSAState is not initialized
//    ippStsMemAllocErr          an internal functional error, see documentation for more details
//    ippStsNoErr                no errors
//
// Parameters:
//    pMu            - input pointer to the pre-computed 64-byte Mu value
//    pPubKey        - input pointer to the public key
//    pSign          - input pointer to the signature
//    pIsSignValid   - output pointer to the verification result (1 - valid, 0 - invalid)
//    pMLDSAState    - input pointer to ML DSA context
//    pScratchBuffer - input pointer to the working buffer of size queried ippsMLDSA_Verify_Mu_BufferGetSize()
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsMLDSA_Verify_Mu, (const Ipp8u* pMu,
                                        const Ipp8u* pPubKey,
                                        const Ipp8u* pSign,
                                        int* pIsSignValid,
                                        IppsMLDSAState* pMLDSAState,
                                        Ipp8u* pScratchBuffer))
/* clang-format on */
{
    IppStatus sts = ippStsErr;
    /* Test input parameters */
    IPP_BAD_PTR3_RET(pMu, pIsSignValid, pPubKey);
    IPP_BAD_PTR3_RET(pSign, pMLDSAState, pScratchBuffer);
    *pIsSignValid = 0;

    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_DSA_VALID_ID(pMLDSAState), ippStsContextMatchErr);

    /* Initialize the temporary storage */
    _cpMLDSAStorage* pStorage = &pMLDSAState->storage;
    pStorage->pStorageData    = pScratchBuffer;

    int verifyBytes = 0;
    sts             = ippsMLDSA_Verify_Mu_BufferGetSize(&verifyBytes, pMLDSAState);
    if (sts != ippStsNoErr) {
        return sts;
    }
    pStorage->bytesCapacity = verifyBytes;

    sts = cp_MLDSA_VerifyCore(pMu, pPubKey, pSign, pIsSignValid, pMLDSAState);

    /* Clear temporary storage */
    IppStatus memReleaseSts = cp_mlStorageReleaseAll(pStorage);
    pStorage->pStorageData  = NULL;
    if (memReleaseSts != ippStsNoErr) {
        return memReleaseSts;
    }

    return sts;
}
