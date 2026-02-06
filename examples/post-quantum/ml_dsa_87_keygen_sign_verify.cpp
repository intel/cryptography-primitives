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
  *  \brief Module-Lattice-Based Digital Signature Standard
  *         (ML-DSA) example.
  *
  *  This example demonstrates usage of ML-DSA key generation,
  *  signing and verification operations.
  *
  *  The example includes all steps, however, the typical scenario is:
  *     Party 1 runs only key generation and signing steps.
  *     Party 2 runs verification step.
  *
  *  Note: This example uses hardware-based random number generation. For full functionality, it
  *  should be launched on a CPU that supports the RDRAND instruction. Alternatively, a custom
  *  RNG can be provided by the user. More details can be found in the rndFunc parameter
  *  description of the ML-DSA documentation.
  *
  *  The ML-DSA scheme is implemented according to the
  *  "Federal Information Processing Standards Publication 204" document:
  *
  *  https://csrc.nist.gov/pubs/fips/204/final
  *
  */

/*! Define the macro to enable ML-DSA usage */
#define IPPCP_PREVIEW_ML_DSA

#include <vector>
#include <iostream>
#include <algorithm>

#include "ippcp.h"
#include "examples_common.h"

/*! Message */
Ipp8u pMessage[] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64 };

int main(void)
{
    /* Internal function status */
    IppStatus status = ippStsNoErr;

    /* Skip the example in case HW RNG is not supported */
    if (!isAvailablePRNG_HW()) {
        printSkippedExampleDetails(
            "ippsMLDSA_KeyGen/ippsMLDSA_Sign/ippsMLDSA_Verify",
            "ML-DSA scheme with ML_DSA_87 parameter",
            "RDRAND instruction is not supported by the CPU but is required\n for this example.");
        return status;
    }

    /* 1. Specify scheme type */
    const IppsMLDSAParamSet schemeType = IppsMLDSAParamSet::ML_DSA_87;
    const Ipp32s msgLen                = sizeof(pMessage);

    /* 2. Allocate and initialize ML-DSA state*/
    int stateSize = 0;
    status        = ippsMLDSA_GetSize(&stateSize);
    if (!checkStatus("ippsMLDSA_GetSize", ippStsNoErr, status)) {
        return status;
    }

    std::vector<Ipp8u> stateBuffer(stateSize);
    IppsMLDSAState* pState = reinterpret_cast<IppsMLDSAState*>(stateBuffer.data());
    status                 = ippsMLDSA_Init(pState, msgLen, schemeType);
    if (!checkStatus("ippsMLDSA_Init", ippStsNoErr, status)) {
        return status;
    }

    /* 3. Query scheme's parameters - sizes of keys and signature */
    IppsMLDSAInfo info;
    status = ippsMLDSA_GetInfo(&info, schemeType);
    if (!checkStatus("ippsMLDSA_GetInfo", ippStsNoErr, status)) {
        return status;
    }

    /* 4. Allocate the required memory */
    std::vector<Ipp8u> privateKey(info.privateKeySize);
    std::vector<Ipp8u> publicKey(info.publicKeySize);
    std::vector<Ipp8u> signature(info.signatureSize);

    /* 5. [Party1] Generate public and private keys */
    int scratchBufferSize = 0;
    status                = ippsMLDSA_KeyGenBufferGetSize(&scratchBufferSize, pState);
    if (!checkStatus("ippsMLDSA_KeyGenBufferGetSize", ippStsNoErr, status)) {
        return status;
    }

    std::vector<Ipp8u> scratchBuffer(scratchBufferSize);
    status = ippsMLDSA_KeyGen(publicKey.data(),
                              privateKey.data(),
                              pState,
                              scratchBuffer.data(),
                              nullptr,
                              nullptr);
    if (!checkStatus("ippsMLDSA_KeyGen", ippStsNoErr, status)) {
        return status;
    }

    /* 6. [Party1] Sign the message using private key */
    status = ippsMLDSA_SignBufferGetSize(&scratchBufferSize, pState);
    if (!checkStatus("ippsMLDSA_SignBufferGetSize", ippStsNoErr, status)) {
        return status;
    }
    std::vector<Ipp8u> signScratchBuffer(scratchBufferSize);

    status = ippsMLDSA_Sign(pMessage,
                            msgLen,
                            nullptr /* context */,
                            0 /* context size */,
                            privateKey.data(),
                            signature.data(),
                            pState,
                            signScratchBuffer.data(),
                            nullptr,
                            nullptr);
    if (!checkStatus("ippsMLDSA_Sign", ippStsNoErr, status)) {
        return status;
    }

    /*------- Message, signature and public key transmission to Party2 -------*/

    /* 7. [Party2] Verify the signature using public key */
    status = ippsMLDSA_VerifyBufferGetSize(&scratchBufferSize, pState);
    if (!checkStatus("ippsMLDSA_VerifyBufferGetSize", ippStsNoErr, status)) {
        return status;
    }
    std::vector<Ipp8u> verifyScratchBuffer(scratchBufferSize);
    int isValid = 0;
    status      = ippsMLDSA_Verify(pMessage,
                              msgLen,
                              nullptr /* context */,
                              0 /* context size */,
                              publicKey.data(),
                              signature.data(),
                              &isValid,
                              pState,
                              verifyScratchBuffer.data());
    if (!checkStatus("ippsMLDSA_Verify", ippStsNoErr, status)) {
        return status;
    }

    PRINT_EXAMPLE_STATUS("ippsMLDSA_KeyGen/ippsMLDSA_Sign/ippsMLDSA_Verify",
                         "ML-DSA scheme with ML_DSA_87 parameter",
                         status == ippStsNoErr && isValid == 1);

    return status;
}
