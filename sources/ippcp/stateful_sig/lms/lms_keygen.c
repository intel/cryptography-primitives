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
//    Name: ippsLMSKeyGen
//
// Purpose: LMS key pair generation.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pPrvKey == NULL
//                            pPubKey == NULL
//                            pBuffer == NULL
//    ippStsBadArgErr         wrong LMS or LMOTS parameters
//                            inside pPrvKey
//    ippStsContextMatchErr   pPrvKey or pPubKey contexts are invalid
//    ippStsNoErr             no errors
//
// Parameters:
//    pPrvKey      pointer to the private key state
//    pPubKey      pointer to the public key state
//    rndFunc      function pointer to generate random numbers. It can be NULL
//                 Security strength must be 8*n bits
//    pRndParam    parameters for rndFunc. It can be NULL
//    pBuffer      pointer to the temporary memory
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsLMSKeyGen, (IppsLMSPrivateKeyState* pPrvKey,
                                  IppsLMSPublicKeyState* pPubKey,
                                  IppBitSupplier rndFunc,
                                  void* pRndParam,
                                  Ipp8u* pBuffer))
/* clang-format on */
{
    IppStatus ippcpSts = ippStsErr;

    /* Check if any of input pointers are NULL */
    IPP_BAD_PTR3_RET(pPrvKey, pPubKey, pBuffer)
    IPP_BADARG_RET(!CP_LMS_VALID_PRIV_KEY_CTX_ID(pPrvKey), ippStsContextMatchErr);
    IPP_BADARG_RET(!CP_LMS_VALID_PUB_KEY_CTX_ID(pPubKey), ippStsContextMatchErr);
    IPP_BADARG_RET(pPrvKey->lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(pPrvKey->lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(pPrvKey->lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(pPrvKey->lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);

    // Set LMOTS and LMS parameters
    cpLMSParams lmsParams;
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMSParams(pPrvKey->lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    ippcpSts = setLMOTSParams(pPrvKey->lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    Ipp32u n = lmotsParams.n;

    Ipp32s pBufferSize;
    IppsLMSAlgoType algoTypes = { pPrvKey->lmotsOIDAlgo, pPrvKey->lmsOIDAlgo };

    ippcpSts = ippsLMSKeyGenBufferGetSize(&pBufferSize, algoTypes);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    // fill private key fields
    pPrvKey->q = 0;

    ippcpSts = cp_rand_num((Ipp32u*)pPrvKey->pSecretSeed, (Ipp32s)n, rndFunc, pRndParam);
    if (ippStsNoErr != ippcpSts) {
        PurgeBlock(pPrvKey->pSecretSeed, (Ipp32s)n); // zeroize the secret seed if error occurs
        return ippcpSts;
    }

    ippcpSts = cp_rand_num((Ipp32u*)pPrvKey->pI, CP_PK_I_BYTESIZE, rndFunc, pRndParam);
    if (ippStsNoErr != ippcpSts) {
        PurgeBlock(pPrvKey->pSecretSeed, (Ipp32s)n); // zeroize the secret seed if error occurs
        PurgeBlock(pPrvKey->pI, CP_PK_I_BYTESIZE);   // zeroize the I if error occurs
        return ippcpSts;
    }
    // calculate the public key as a root of the LMS tree
    ippcpSts = cp_lms_tree_hash(/*isKeyGen*/ 1,
                                pPrvKey->pSecretSeed,
                                pPrvKey->pI,
                                pPubKey->T1,
                                /*empty*/ 0,
                                pBuffer,
                                pPrvKey->pExtraBuf,
                                pPrvKey->extraBufSize,
                                &lmsParams,
                                &lmotsParams);
    PurgeBlock(pBuffer, pBufferSize);                // zeroize the temporary memory
    if (ippStsNoErr != ippcpSts) {
        PurgeBlock(pPrvKey->pSecretSeed, (Ipp32s)n); // zeroize the secret seed if error occurs
        PurgeBlock(pPrvKey->pI, CP_PK_I_BYTESIZE);   // zeroize the I if error occurs
        return ippcpSts;
    }
    // copy I from private key to public
    CopyBlock(pPrvKey->pI, pPubKey->I, CP_PK_I_BYTESIZE);

    return ippcpSts;
}
