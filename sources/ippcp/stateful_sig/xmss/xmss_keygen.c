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

#include "owndefs.h"
#include "stateful_sig/xmss_internal/xmss.h"
#include "stateful_sig/common.h"

/*F*
//    Name: ippsXMSSKeyGen
//
// Purpose: XMSS public and private keys generation.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pPrvKey == NULL
//                            pPubKey == NULL
//                            pBuffer == NULL
//    ippStsBadArgErr         pPrvKey->OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         pPrvKey->OIDAlgo <= 0
//    ippStsNoErr             no errors
//
// Parameters:
//    pPrvKey      pointer to the private key state
//    pPubKey      pointer to the public key state
//    rndFunc      function pointer to generate random numbers. It can be NULL
//    pRndParam    parameters for rndFunc. It can be NULL
//    pBuffer      pointer to the temporary memory
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsXMSSKeyGen, (IppsXMSSPrivateKeyState* pPrvKey,
                                   IppsXMSSPublicKeyState* pPubKey,
                                   IppBitSupplier rndFunc,
                                   void* pRndParam,
                                   Ipp8u* pBuffer))
/* clang-format on */
{
    IppStatus retCode = ippStsNoErr;

    /* Check if any of input pointers are NULL */
    IPP_BAD_PTR1_RET(pPrvKey)
    IPP_BAD_PTR1_RET(pPubKey)
    /* Check if temporary buffer is NULL */
    IPP_BAD_PTR1_RET(pBuffer)
    IPP_BADARG_RET(pPrvKey->OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(pPrvKey->OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);

    /* Parameters of the current XMSS */
    Ipp32s h = 0;
    cpWOTSParams params;
    retCode = cp_xmss_set_params(pPubKey->OIDAlgo, &h, &params);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
    Ipp32s n = params.n;

    // description of internals for OTS Hash / L-tree / Hash tree address is following
    // +-----------------------------------------------------+
    // | layer address                              (32 bits)|
    // +-----------------------------------------------------+
    // | tree address                               (64 bits)|
    // +-----------------------------------------------------+
    // | type = 0 / 1 / 2                           (32 bits)|
    // +-----------------------------------------------------+
    // | OTS address / L-tree address / Padding = 0 (32 bits)|
    // +-----------------------------------------------------+
    // | chain address / tree height                (32 bits)|
    // +-----------------------------------------------------+
    // | hash address / tree index                  (32 bits)|
    // +-----------------------------------------------------+
    // | keyAndMask                                 (32 bits)|
    // +-----------------------------------------------------+
    Ipp8u adrs[ADRS_SIZE] = {
        0, 0, 0, 0,             //  0; 4
        0, 0, 0, 0, 0, 0, 0, 0, //  4; 12
        0, 0, 0, 0,             // 12; 16
        0, 0, 0, 0,             // 16; 20
        0, 0, 0, 0,             // 20; 24
        0, 0, 0, 0,             // 24; 28
        0, 0, 0, 0              // 28; 32
    };

    // fill private key fields
    pPrvKey->idx = 0;

    retCode = cp_rand_num((Ipp32u*)pPrvKey->pSecretSeed, n, rndFunc, pRndParam);
    if (ippStsNoErr != retCode) {
        PurgeBlock(pPrvKey->pSecretSeed, n); // zeroize the secret seed if error occurs
        return retCode;
    }

    retCode = cp_rand_num((Ipp32u*)pPrvKey->pSK_PRF, n, rndFunc, pRndParam);
    if (ippStsNoErr != retCode) {
        PurgeBlock(pPrvKey->pSecretSeed, n); // zeroize the secret seed if error occurs
        PurgeBlock(pPrvKey->pSK_PRF, n);     // zeroize the SK_PRF if error occurs
        return retCode;
    }

    retCode = cp_rand_num((Ipp32u*)pPrvKey->pPublicSeed, n, rndFunc, pRndParam);
    if (ippStsNoErr != retCode) {
        PurgeBlock(pPrvKey->pSecretSeed, n); // zeroize the secret seed if error occurs
        PurgeBlock(pPrvKey->pSK_PRF, n);     // zeroize the SK_PRF if error occurs
        PurgeBlock(pPrvKey->pPublicSeed, n); // zeroize the public seed if error occurs
        return retCode;
    }

    Ipp32s pBufferSize;
    retCode = ippsXMSSKeyGenBufferGetSize(&pBufferSize, pPrvKey->OIDAlgo);
    if (ippStsNoErr != retCode) {
        PurgeBlock(pPrvKey->pSecretSeed, n); // zeroize the secret seed if error occurs
        PurgeBlock(pPrvKey->pSK_PRF, n);     // zeroize the SK_PRF if error occurs
        PurgeBlock(pPrvKey->pPublicSeed, n); // zeroize the public seed if error occurs
        return retCode;
    }

    retCode = cp_xmss_tree_hash(/*isKeyGen*/ 1,
                                pPrvKey,
                                adrs,
                                pPrvKey->pRoot,
                                /*empty*/ 0,
                                pBuffer,
                                h,
                                &params);
    PurgeBlock(pBuffer, pBufferSize);        // zeroize the temporary memory
    if (ippStsNoErr != retCode) {
        PurgeBlock(pPrvKey->pSecretSeed, n); // zeroize the secret seed if error occurs
        PurgeBlock(pPrvKey->pSK_PRF, n);     // zeroize the SK_PRF if error occurs
        PurgeBlock(pPrvKey->pPublicSeed, n); // zeroize the public seed if error occurs
        return retCode;
    }

    // fill public key fields
    CopyBlock(pPrvKey->pRoot, pPubKey->pRoot, n);
    CopyBlock(pPrvKey->pPublicSeed, pPubKey->pSeed, n);

    return retCode;
}
