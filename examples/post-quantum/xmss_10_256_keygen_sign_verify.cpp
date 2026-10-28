/*************************************************************************
* Copyright (C) 2026 Intel Corporation
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
  *  \brief eXtended Merkle Signature Scheme (XMSS) example
  *
  *  This example demonstrates usage of XMSS key generation, signing
  *  and verification of the produced signature.
  *
  *  The XMSS algorithm is implemented according to the
  *  "XMSS: eXtended Merkle Signature Scheme" document:
  *
  *  https://www.rfc-editor.org/info/rfc8391
  *
  */

#include <memory>

#include "ippcp.h"
#include "examples_common.h"

/*! Algorithm ID for XMSS */
static const IppsXMSSAlgo algo = IppsXMSSAlgo::XMSS_SHA2_10_256; // 0x00000001

/*! Message */
static const Ipp8u pMsg[] = { 0x04, 0x3d, 0x64, 0x00, 0x10, 0x3b, 0x16, 0x0c, 0xf1, 0x89,
                              0xb4, 0xcf, 0xff, 0x08, 0x06, 0xfe, 0xe3, 0xe1, 0x56, 0x7f,
                              0x2c, 0x31, 0x71, 0x0f, 0x82, 0x84, 0x52, 0x74, 0xf6, 0xed,
                              0x23, 0x8e, 0x14, 0xde, 0x4d, 0x53, 0x99, 0x86, 0x88, 0x99,
                              0xab, 0x6b, 0xcf, 0x00, 0x98, 0x08, 0xb8, 0xca };

int main(void)
{
    /* Skip the example in case HW RNG is not supported */
    if (!isAvailableTRNG_HW()) {
        printSkippedExampleDetails(
            "ippsXMSSKeyGen/ippsXMSSSign",
            "XMSS with XMSS_SHA2_10_256 parameters",
            "RDSEED instruction is not supported by the CPU but is required\n for this example.");
        return ippStsNoErr;
    }

    /* Internal function status */
    IppStatus status = ippStsNoErr;

    /* Deleter to use in unique_ptr to clean the memory during the object's destruction */
    auto toIpp8uDeleter = [](auto* pData) { delete[] (Ipp8u*)pData; };

    const Ipp32s msgLen = sizeof(pMsg);

    /* 1. Get the scratch buffer size for key generation */
    int buffKeyGenSize;
    status = ippsXMSSKeyGenBufferGetSize(&buffKeyGenSize, algo);
    if (!checkStatus("ippsXMSSKeyGenBufferGetSize", ippStsNoErr, status))
        return status;

    /* 2. Get the scratch buffer size for signing the message */
    int buffSignSize;
    status = ippsXMSSSignBufferGetSize(&buffSignSize, msgLen, algo);
    if (!checkStatus("ippsXMSSSignBufferGetSize", ippStsNoErr, status))
        return status;

    /* 3. Get the scratch buffer size for verifying the message */
    int buffVerifySize;
    status = ippsXMSSVerifyBufferGetSize(&buffVerifySize, msgLen, algo);
    if (!checkStatus("ippsXMSSVerifyBufferGetSize", ippStsNoErr, status))
        return status;

    /* 4. Allocate memory for scratch buffers */
    std::unique_ptr<Ipp8u[]> pScratchKeyGenBuffer(new Ipp8u[buffKeyGenSize]);
    std::unique_ptr<Ipp8u[]> pScratchSignBuffer(new Ipp8u[buffSignSize]);
    std::unique_ptr<Ipp8u[]> pScratchVerifyBuffer(new Ipp8u[buffVerifySize]);

    /* 5. Get the XMSS private key state size */
    int ippcpPrivKeySize;
    status = ippsXMSSPrivateKeyStateGetSize(&ippcpPrivKeySize, algo);
    if (!checkStatus("ippsXMSSPrivateKeyStateGetSize", ippStsNoErr, status))
        return status;

    /* 6. Get the XMSS public key state size */
    int ippcpPubKeySize;
    status = ippsXMSSPublicKeyStateGetSize(&ippcpPubKeySize, algo);
    if (!checkStatus("ippsXMSSPublicKeyStateGetSize", ippStsNoErr, status))
        return status;

    /* 7. Allocate memory for XMSS key states */
    std::unique_ptr<IppsXMSSPrivateKeyState, decltype(toIpp8uDeleter)> pPrvKey(
        (IppsXMSSPrivateKeyState*)(new Ipp8u[ippcpPrivKeySize]),
        toIpp8uDeleter);

    std::unique_ptr<IppsXMSSPublicKeyState, decltype(toIpp8uDeleter)> pPubKey(
        (IppsXMSSPublicKeyState*)(new Ipp8u[ippcpPubKeySize]),
        toIpp8uDeleter);

    /* 8. Initialize XMSS key states */
    status = ippsXMSSInitKeyPair(algo, pPrvKey.get(), pPubKey.get());
    if (!checkStatus("ippsXMSSInitKeyPair", ippStsNoErr, status))
        return status;

    /* 9. Generate XMSS keys (NULL random generator means the hardware RDSEED is used) */
    status =
        ippsXMSSKeyGen(pPrvKey.get(), pPubKey.get(), nullptr, nullptr, pScratchKeyGenBuffer.get());
    if (!checkStatus("ippsXMSSKeyGen", ippStsNoErr, status))
        return status;

    /* 10. Get the XMSS signature state size */
    int sigBuffSize;
    status = ippsXMSSSignatureStateGetSize(&sigBuffSize, algo);
    if (!checkStatus("ippsXMSSSignatureStateGetSize", ippStsNoErr, status))
        return status;

    /* 11. Allocate memory for the XMSS signature state */
    std::unique_ptr<IppsXMSSSignatureState, decltype(toIpp8uDeleter)> pSignature(
        (IppsXMSSSignatureState*)(new Ipp8u[sigBuffSize]),
        toIpp8uDeleter);

    /* 12. Initialize XMSS signature state */
    status = ippsXMSSInitSignature(algo, pSignature.get());
    if (!checkStatus("ippsXMSSInitSignature", ippStsNoErr, status))
        return status;

    /* 13. Sign the message (the private key state is updated: each leaf can be used only once) */
    status = ippsXMSSSign(pMsg, msgLen, pPrvKey.get(), pSignature.get(), pScratchSignBuffer.get());
    if (!checkStatus("ippsXMSSSign", ippStsNoErr, status))
        return status;

    /* 14. Verify the produced signature */
    int is_valid = 0;
    status       = ippsXMSSVerify(pMsg,
                            msgLen,
                            pSignature.get(),
                            &is_valid,
                            pPubKey.get(),
                            pScratchVerifyBuffer.get());
    if (!checkStatus("ippsXMSSVerify", ippStsNoErr, status))
        return status;

    PRINT_EXAMPLE_STATUS("ippsXMSSSign", "XMSS Signing", status == ippStsNoErr && is_valid == 1);

    return status;
}
