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
  *  \brief Leighton-Micali Hash-Based Signatures (LMS) example
  *
  *  This example demonstrates usage of LMS key and signature generation.
  *
  *  The LMS algorithm is implemented according to the
  *  "Leighton-Micali Hash-Based Signatures" document:
  *
  *  https://www.rfc-editor.org/info/rfc8554
  *
  */

/*! Define the macro to enable LMS usage */
#define IPPCP_PREVIEW_LMS

#include <memory>

#include "ippcp.h"
#include "examples_common.h"

/*! Algorithm ID for LMS */
IppsLMSAlgo lmsAlgo = IppsLMSAlgo::LMS_SHA256_M24_H15; // 12

/*! Algorithm ID for OTS (one-time signature) */
IppsLMOTSAlgo lmotsAlgo = IppsLMOTSAlgo::LMOTS_SHA256_N24_W4; // 7

/*! Message */
Ipp8u pMsg[] = { 0x04, 0x3d, 0x64, 0x00, 0x10, 0x3b, 0x16, 0x0c, 0xf1, 0x89, 0xb4, 0xcf, 0xff,
                 0x08, 0x06, 0xfe, 0xe3, 0xe1, 0x56, 0x7f, 0x2c, 0x31, 0x71, 0x0f, 0x82, 0x84,
                 0x52, 0x74, 0xf6, 0xed, 0x23, 0x8e, 0x14, 0xde, 0x4d, 0x53, 0x99, 0x86, 0x88,
                 0x99, 0xab, 0x6b, 0xcf, 0x00, 0x98, 0x08, 0xb8, 0xca, 0x30, 0x81, 0xed, 0x11,
                 0xaa, 0x70, 0x35, 0x52, 0x90, 0xfd, 0x86, 0x98, 0xd4, 0xc1, 0x77, 0xc1, 0x89,
                 0x4c, 0xd8, 0xb8, 0xd3, 0x36, 0x7f, 0xd0, 0xf3, 0x00, 0xef, 0x62, 0x83, 0x02,
                 0x0d, 0x09, 0x1c, 0x27, 0x35, 0x6d, 0xaf, 0xad, 0xdb, 0xed, 0x96, 0x21, 0x8a,
                 0x19, 0x56, 0x7b, 0x99, 0x9a, 0xcd, 0x53, 0x02, 0xa5, 0x11, 0xd4, 0xf1, 0x65,
                 0xef, 0x9c, 0xbe, 0x85, 0x5d, 0xcc, 0x73, 0x1b, 0x16, 0xdd, 0x13, 0x6e, 0x5c,
                 0x44, 0x15, 0x8b, 0xf1, 0xe9, 0x8c, 0xc5, 0x9c, 0x6f, 0x6c, 0xb2 };

/* Deleter to use in unique_ptr to clean the memory during the object's destruction */

int main(void)
{
    /* Skip the example in case HW RNG is not supported */
    if (!isAvailablePRNG_HW()) {
        printSkippedExampleDetails(
            "ippsLMSKeyGen/ippsLMSSign",
            "LMS with LMS_SHA256_M24_H15 and LMOTS_SHA256_N24_W4 parameters",
            "RDRAND instruction is not supported by the CPU but is required\n for this example.");
        return ippStsNoErr;
    }

    auto toIpp8uDeleter = [](auto* pData) { delete[] (Ipp8u*)pData; };

    /* Internal function status */
    IppStatus status = ippStsNoErr;

    const Ipp32s msgLen       = sizeof(pMsg);
    const Ipp32s extraBufSize = 1488; // Extra buffer size for the LMS key generation = 62 * 24

    /* Create an algorithm ID to put into the ippsLMS functions */
    const IppsLMSAlgoType algoType = { lmotsAlgo, lmsAlgo };

    /* 1. Get the scratch buffer size for key generation */
    int buffKeyGenSize;
    status = ippsLMSKeyGenBufferGetSize(&buffKeyGenSize, algoType);
    if (!checkStatus("ippsLMSKeyGenBufferGetSize", ippStsNoErr, status))
        return status;

    /* 2. Get the scratch buffer size for signing the message */
    int buffSignSize;
    status = ippsLMSSignBufferGetSize(&buffSignSize, msgLen, algoType);
    if (!checkStatus("ippsLMSSignBufferGetSize", ippStsNoErr, status))
        return status;

    /* 3. Allocate memory for scratch buffers */
    std::unique_ptr<Ipp8u, decltype(toIpp8uDeleter)> pScratchKeyGenBuffer(new Ipp8u[buffKeyGenSize],
                                                                          toIpp8uDeleter);
    std::unique_ptr<Ipp8u, decltype(toIpp8uDeleter)> pScratchSignBuffer(new Ipp8u[buffSignSize],
                                                                        toIpp8uDeleter);

    /* 4. Get the LMS private key state size */
    int ippcpPrivKeySize;
    status = ippsLMSPrivateKeyStateGetSize(&ippcpPrivKeySize, algoType, extraBufSize);
    if (!checkStatus("ippsLMSPrivateKeyStateGetSize", ippStsNoErr, status))
        return status;

    /* 5. Get the LMS public key state size */
    int ippcpPubKeySize;
    status = ippsLMSPublicKeyStateGetSize(&ippcpPubKeySize, algoType);
    if (!checkStatus("ippsLMSPublicKeyStateGetSize", ippStsNoErr, status))
        return status;

    /* 6. Allocate memory for LMS key states */
    std::unique_ptr<IppsLMSPrivateKeyState, decltype(toIpp8uDeleter)> pPrvKey(
        (IppsLMSPrivateKeyState*)(new Ipp8u[ippcpPrivKeySize]),
        toIpp8uDeleter);

    std::unique_ptr<IppsLMSPublicKeyState, decltype(toIpp8uDeleter)> pPubKey(
        (IppsLMSPublicKeyState*)(new Ipp8u[ippcpPubKeySize]),
        toIpp8uDeleter);

    /* 7. Initialize LMS key states */
    status = ippsLMSInitKeyPair(algoType, extraBufSize, pPrvKey.get(), pPubKey.get());
    if (!checkStatus("ippsLMSInitKeyPair", ippStsNoErr, status))
        return status;

    /* 8. Generate LMS keys */
    status =
        ippsLMSKeyGen(pPrvKey.get(), pPubKey.get(), nullptr, nullptr, pScratchKeyGenBuffer.get());
    if (!checkStatus("ippsLMSKeyGen", ippStsNoErr, status))
        return status;

    /* 9. Get the LMS signature state size */
    int sigBuffSize;
    status = ippsLMSSignatureStateGetSize(&sigBuffSize, algoType);
    if (!checkStatus("ippsLMSSignatureStateGetSize", ippStsNoErr, status))
        return status;

    /* 10. Allocate memory for the LMS signature buffer */
    std::unique_ptr<IppsLMSSignatureState, decltype(toIpp8uDeleter)> pSignature(
        (IppsLMSSignatureState*)(new Ipp8u[sigBuffSize]),
        toIpp8uDeleter);

    /* 11. Initialize LMS signature state */
    status = ippsLMSInitSignature(algoType, pSignature.get());
    if (!checkStatus("ippsLMSInitSignature", ippStsNoErr, status))
        return status;

    /* 12. Sign the message */
    status = ippsLMSSign(pMsg,
                         msgLen,
                         pPrvKey.get(),
                         pSignature.get(),
                         nullptr,
                         nullptr,
                         pScratchSignBuffer.get());
    if (!checkStatus("ippsLMSSign", ippStsNoErr, status))
        return status;

    /* Check that generated signature is correct */
    /* Get the scratch buffer size for verifying the message */
    int buffVerifySize;
    status = ippsLMSVerifyBufferGetSize(&buffVerifySize, sizeof(pMsg), algoType);
    if (!checkStatus("ippsLMSVerifyBufferGetSize", ippStsNoErr, status))
        return status;

    std::unique_ptr<Ipp8u, decltype(toIpp8uDeleter)> pScratchVerifyBuffer(new Ipp8u[buffVerifySize],
                                                                          toIpp8uDeleter);

    int is_valid = 0;
    status       = ippsLMSVerify(pMsg,
                           sizeof(pMsg),
                           pSignature.get(),
                           &is_valid,
                           pPubKey.get(),
                           pScratchVerifyBuffer.get());
    if (!checkStatus("ippsLMSVerify", ippStsNoErr, status))
        return status;

    PRINT_EXAMPLE_STATUS("ippsLMSSign", "LMS Signing", status == ippStsNoErr && is_valid == 1);

    return status;
}
