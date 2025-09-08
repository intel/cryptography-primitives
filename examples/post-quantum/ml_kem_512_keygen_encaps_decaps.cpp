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

/*!
  *
  *  \file
  *
  *  \brief Module-Lattice-Based Key-Encapsulation Mechanism Standard
  *         (ML-KEM) example.
  *
  *  This example demonstrates usage of ML-KEM key generation,
  *  encapsulation and decapsulation operations.
  *
  *  The example includes all steps of the KEM protocol, however, the typical scenario is:
  *     Party 1 runs only key generation and decapsulation steps.
  *     Party 2 runs encapsulation step.
  *
  *  Note: This example uses hardware-based random number generation. For full functionality, it
  *  should be launched on a CPU that supports the RDRAND instruction. Alternatively, a custom
  *  RNG can be provided by the user. More details can be found in the rndFunc parameter 
  *  description of the ML-KEM documentation.
  *
  *  The ML-KEM scheme is implemented according to the
  *  "Federal Information Processing Standards Publication 203" document:
  *
  *  https://csrc.nist.gov/pubs/fips/203/final
  *
  */

/*! Define the macro to enable ML-KEM usage */
#define IPPCP_PREVIEW_ML_KEM

#include <vector>
#include <iostream>
#include <algorithm>

#include "ippcp.h"
#include "examples_common.h"

int main(void)
{
    /* Internal function status */
    IppStatus status = ippStsNoErr;

    /* Skip the example in case HW RNG is not supported */
    if (!isAvailablePRNG_HW()) {
        printSkippedExampleDetails(
            "ippsMLKEM_KeyGen/ippsMLKEM_Encaps/ippsMLKEM_Decaps",
            "ML-KEM scheme with IPPCP_ML_KEM_512 parameter",
            "RDRAND instruction is not supported by the CPU but is required\n for this example.");
        return ippStsNoOperation;
    }


    /* 1. Specify scheme type */
    const IppsMLKEMParamSet schemeType = IPPCP_ML_KEM_512;

    /* 2. Allocate and initialize ML-KEM state*/
    int stateSize = 0;
    status        = ippsMLKEM_GetSize(&stateSize, schemeType);
    if (!checkStatus("ippsMLKEM_GetSize", ippStsNoErr, status)) {
        return status;
    }

    std::vector<Ipp8u> stateBuffer(stateSize);
    IppsMLKEMState* pState = reinterpret_cast<IppsMLKEMState*>(stateBuffer.data());
    status                 = ippsMLKEM_Init(pState, schemeType);
    if (!checkStatus("ippsMLKEM_Init", ippStsNoErr, status)) {
        return status;
    }

    /* 3. Query scheme's parameters - sizes of keys, shared secret and ciphertext */
    IppsMLKEMInfo info;
    status = ippsMLKEM_GetInfo(&info, schemeType);
    if (!checkStatus("ippsMLKEM_GetInfo", ippStsNoErr, status)) {
        return status;
    }

    /* 4. Allocate the required memory */

    /* Encapsulation and decapsulation keys */
    std::vector<Ipp8u> pEncKey(info.encapsKeySize);
    std::vector<Ipp8u> pDecKey(info.decapsKeySize);

    /* Cipher text (encapsulated shared secret) */
    std::vector<Ipp8u> pCipherText(info.cipherTextSize);

    /* Shared secret of the two parties */
    std::vector<Ipp8u> pSharedSecret1(info.sharedSecretSize);
    std::vector<Ipp8u> pSharedSecret2(info.sharedSecretSize);

    /* 5. [Party1] Generate encapsulation and decapsulation keys */
    int scratchBufferSize = 0;
    status                = ippsMLKEM_KeyGenBufferGetSize(&scratchBufferSize, pState);
    if (!checkStatus("ippsMLKEM_KeyGenBufferGetSize", ippStsNoErr, status)) {
        return status;
    }

    std::vector<Ipp8u> pScratchBuffer(scratchBufferSize);
    status = ippsMLKEM_KeyGen(pEncKey.data(),
                              pDecKey.data(),
                              pState,
                              pScratchBuffer.data(),
                              nullptr,
                              nullptr);
    if (!checkStatus("ippsMLKEM_KeyGen", ippStsNoErr, status)) {
        return status;
    }

    /*------------------------- pEncKey transmission to Party2 -------------------------*/

    /* 6. [Party2] Generate the shared secret and encapsulate it with received pEncKey */
    status = ippsMLKEM_EncapsBufferGetSize(&scratchBufferSize, pState);
    if (!checkStatus("ippsMLKEM_EncapsBufferGetSize", ippStsNoErr, status)) {
        return status;
    }

    std::vector<Ipp8u> pEncapsScratchBuffer(scratchBufferSize);
    status = ippsMLKEM_Encaps(pEncKey.data(),
                              pCipherText.data(),
                              pSharedSecret2.data(),
                              pState,
                              pEncapsScratchBuffer.data(),
                              nullptr,
                              nullptr);
    if (!checkStatus("ippsMLKEM_Encaps", ippStsNoErr, status)) {
        return status;
    }

    /*------------------------ pCipherText transmission to Party1 ------------------------*/

    /* 7. [Party1] Decapsulate the received pCipherText to pSharedSecret1 */
    status = ippsMLKEM_DecapsBufferGetSize(&scratchBufferSize, pState);
    if (!checkStatus("ippsMLKEM_DecapsBufferGetSize", ippStsNoErr, status)) {
        return status;
    }
    std::vector<Ipp8u> pDecapsScratchBuffer(scratchBufferSize);
    status = ippsMLKEM_Decaps(pDecKey.data(),
                              pCipherText.data(),
                              pSharedSecret1.data(),
                              pState,
                              pDecapsScratchBuffer.data());
    if (!checkStatus("ippsMLKEM_Decaps", ippStsNoErr, status)) {
        return status;
    }

    /*------------------ Both parties should have the same shared secret ------------------*/

    bool isSecretsEqual =
        std::equal(pSharedSecret1.begin(), pSharedSecret1.end(), pSharedSecret2.begin());
    if (!isSecretsEqual) {
        std::cout << "ERROR: Shared secrets of two parties do not match\n";
        status = -1;
    }

    PRINT_EXAMPLE_STATUS("ippsMLKEM_KeyGen/ippsMLKEM_Encaps/ippsMLKEM_Decaps",
                         "ML-KEM scheme with IPPCP_ML_KEM_512 parameter",
                         !status);

    return status;
}
