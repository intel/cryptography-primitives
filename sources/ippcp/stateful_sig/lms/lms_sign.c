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
#include "stateful_sig/lms_internal/lms.h"
#include "stateful_sig/common.h"

/*F*
//    Name: ippsLMSSign
//
// Purpose: LMS signature generation.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMsg == NULL
//                            pPrvKey == NULL
//                            pSign == NULL
//                            pBuffer == NULL
//    ippStsBadArgErr         wrong LMS or LMOTS parameters
//                            inside pPrvKey
//    ippStsContextMatchErr   pSign or pPrvKey contexts are invalid
//    ippStsLengthErr         msgLen < 1
//    ippStsLengthErr         msgLen > IPP_MAX_32S - (CP_PK_I_BYTESIZE + 4 + 2 + n)
//    ippStsNoErr             no errors
//    ippStsOutOfRangeErr     private key will not be valid any longer after executing the function
//
// Parameters:
//    pMsg           pointer to the message data buffer
//    msgLen         message buffer length
//    pPrvKey        pointer to the private key
//    pSign          pointer to the signature
//    rndFunc        function pointer to generate random numbers. It can be NULL
//    pRndParam      parameters for rndFunc. It can be NULL
//    pBuffer        pointer to the temporary memory
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsLMSSign, (const Ipp8u* pMsg,
                                const Ipp32s msgLen,
                                IppsLMSPrivateKeyState* pPrvKey,
                                IppsLMSSignatureState* pSign,
                                IppBitSupplier rndFunc,
                                void* pRndParam,
                                Ipp8u* pBuffer))
/* clang-format on */
{
    IppStatus ippcpSts = ippStsNoErr;

    /* Check if any of input pointers are NULL */
    IPP_BAD_PTR4_RET(pMsg, pPrvKey, pSign, pBuffer)
    /* Check msg length */
    IPP_BADARG_RET(msgLen < 1, ippStsLengthErr)
    IPP_BADARG_RET(!CP_LMS_VALID_CTX_ID(pPrvKey), ippStsContextMatchErr);
    IPP_BADARG_RET(!CP_LMS_VALID_CTX_ID(pSign), ippStsContextMatchErr);
    IPP_BADARG_RET(pPrvKey->lmsOIDAlgo > LMS_SHA256_M24_H25, ippStsBadArgErr);
    IPP_BADARG_RET(pPrvKey->lmsOIDAlgo < LMS_SHA256_M32_H5, ippStsBadArgErr);
    IPP_BADARG_RET(pPrvKey->lmotsOIDAlgo > LMOTS_SHA256_N24_W8, ippStsBadArgErr);
    IPP_BADARG_RET(pPrvKey->lmotsOIDAlgo < LMOTS_SHA256_N32_W1, ippStsBadArgErr);

    // Set LMOTS and LMS parameters
    cpLMSParams lmsParams;
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMSParams(pPrvKey->lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    ippcpSts = setLMOTSParams(pPrvKey->lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    Ipp32u n = lmotsParams.n;
    Ipp32u h = lmsParams.h;
    IPP_BADARG_RET(msgLen > (Ipp32s)((IPP_MAX_32S) - (CP_PK_I_BYTESIZE + 4 + 2 + n)),
                   ippStsLengthErr);

    Ipp32s pBufferSize;
    IppsLMSAlgoType algoTypes = { pPrvKey->lmotsOIDAlgo, pPrvKey->lmsOIDAlgo };
    ippcpSts                  = ippsLMSSignBufferGetSize(&pBufferSize, msgLen, algoTypes);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    // set idx of current private key
    pSign->_q = pPrvKey->idx;

    // fill _lmotsSig
    ippcpSts = cp_rand_num((Ipp32u*)pSign->_lmotsSig.pC, (Ipp32s)n, rndFunc, pRndParam);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    ippcpSts = cp_lms_OTS_sign(
        pMsg,
        msgLen,
        pPrvKey->pSecretSeed,
        pPrvKey->pI,
        pSign->_q,
        pSign->_lmotsSig.pC,
        pSign->_lmotsSig.pY,
        pBuffer,
        &lmotsParams); // temp size: CP_PK_I_BYTESIZE + 4 + 2 + n + max(msgLen, 1 + n)
    if (ippStsNoErr != ippcpSts) {
        PurgeBlock(pBuffer, pBufferSize);
        return ippcpSts;
    }

    // pAuthPath
    ippcpSts = cp_lms_tree_hash(/*isKeyGen*/ 0,
                                pPrvKey->pSecretSeed,
                                pPrvKey->pI,
                                pSign->_pAuthPath,
                                pPrvKey->idx,
                                pBuffer,
                                pPrvKey->pExtraBuf,
                                pPrvKey->extraBufSize,
                                &lmsParams,
                                &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    // zeroize the temporary memory if everything else was successful
    PurgeBlock(pBuffer, pBufferSize);

    // during the next call another private key should be used to sign
    pPrvKey->idx++;

    // pass the error if we are out of secret keys
    // Note: there is no overflow since the maximum value for h is 20 according to the Spec
    if (pPrvKey->idx == (Ipp32u)(1 << h)) {
        return ippStsOutOfRangeErr;
    }

    return ippcpSts;
}
