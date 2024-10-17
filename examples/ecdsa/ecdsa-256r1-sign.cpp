/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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

// /*!
//   *
//   *  \file
//   *
//   *  \brief ECDSA signature example
//   *
//   *  This example showcases the utilization of the elliptic curve
//   *  digital signature algorithm(ECDSA) over NIST P-256 curve with
//   *  DSA scheme for signature generation.
//   *
//   */

#include <string.h>
#include <memory>

#include <vector>

#include "ippcp.h"
#include "bignum.h"
#include "utils.h"
#include "examples_common.h"

/* Message digest */
static const Ipp8u msg_digest[] = { 0x56,0xec,0x33,0xa1,0xa6,0xe7,0xc4,0xdb,0x77,0x03,0x90,0x1a,0xfb,0x2e,0x1e,0x4e,
                                    0x50,0x09,0xfe,0x04,0x72,0x89,0xc5,0xc2,0x42,0x13,0x6c,0xe3,0xb7,0xf6,0xac,0x44 };

/* Regular and ephemeral private keys */
static const Ipp8u d[]          = { 0x64,0xb4,0x72,0xda,0x6d,0xa5,0x54,0xca,0xac,0x3e,0x4e,0x0b,0x13,0xc8,0x44,0x5b,
                                    0x1a,0x77,0xf4,0x59,0xee,0xa8,0x4f,0x1f,0x58,0x8b,0x5f,0x71,0x3d,0x42,0x9b,0x51 };
static const Ipp8u k[]          = { 0xde,0x68,0x2a,0x64,0x87,0x07,0x67,0xb9,0x33,0x5d,0x4f,0x82,0x47,0x62,0x4a,0x3b,
                                    0x7f,0x3c,0xe9,0xf9,0x45,0xf2,0x80,0xa2,0x61,0x6a,0x90,0x4b,0xb1,0xbb,0xa1,0x94 };

/* signature */
static const Ipp8u r[]          = { 0xac,0xc2,0xc8,0x79,0x6f,0x5e,0xbb,0xca,0x7a,0x5a,0x55,0x6a,0x1f,0x6b,0xfd,0x2a,
                                    0xed,0x27,0x95,0x62,0xd6,0xe3,0x43,0x88,0x5b,0x79,0x14,0xb5,0x61,0x80,0xac,0xf3 };
static const Ipp8u s[]          = { 0x03,0x89,0x05,0xcc,0x2a,0xda,0xcd,0x3c,0x5a,0x17,0x6f,0xe9,0x18,0xb2,0x97,0xef,
                                    0x1c,0x37,0xf7,0x2b,0x26,0x76,0x6c,0x78,0xb2,0xa6,0x05,0xca,0x19,0x78,0xf7,0x8b };

static const unsigned int primeBitSize = 256;

static const unsigned int ordWordSize   = 8;
static const unsigned int msgWordSize   = 8;
static const unsigned int primeWordSize = 8;

/*! Main function */
int main(void)
{
    /* Internal function status */
    IppStatus status = ippStsNoErr;

    /* Size of the context of a GF field. It will be set up in ippsGFpGetSize() */
    int GFpBuffSize = 0;

    /* Size of the context of an elliptic curve field. It will be set up in ippsGFpECGetSize() */
    int GFpECBuffSize = 0;

    /* Size of the scratch buffer */
    int scratchSize = 0;

    /* Create integers R and S for the digital signature */
    BigNumber bnR(NULL, ordWordSize, ippBigNumPOS);
    BigNumber bnS(NULL, ordWordSize, ippBigNumPOS);

    /* Initialize message digest to be digitally signed i.e. encrypted with a private key */
    BigNumber bnMsgDigest((const Ipp32u *)msg_digest, msgWordSize, ippBigNumPOS);
    
    /* Initialize regular and ephemeral private keys of the signer */
    BigNumber bnRegPrivate((const Ipp32u *)d, primeWordSize, ippBigNumPOS);
    BigNumber bnEphPrivate((const Ipp32u *)k, primeWordSize, ippBigNumPOS);

    /* Initialize known digital signatures */
    BigNumber bnRref((const Ipp32u *)r, ordWordSize, ippBigNumPOS);
    BigNumber bnSref((const Ipp32u *)s, ordWordSize, ippBigNumPOS);

    /* 1. Get the size of the context of a GF field */
    status = ippsGFpGetSize(primeBitSize, &GFpBuffSize);
    if (!checkStatus("ippsGFpGetSize", ippStsNoErr, status))
        return status;

    /* 2. Allocate memory for the GF field context */
    std::vector<Ipp8u> pGFpBuff(GFpBuffSize);
    IppsGFpState *pGF = (IppsGFpState *)(pGFpBuff.data());

    /* 3. Initialize the context of a prime finite field GF */
    status = ippsGFpInitFixed(primeBitSize, ippsGFpMethod_p256r1(), pGF);
    if (!checkStatus("ippsGFpInitFixed", ippStsNoErr, status))
        return status;

    /* 4. Get the size of an elliptic curve over the finite field */
    status = ippsGFpECGetSize(pGF, &GFpECBuffSize);
    if (!checkStatus("ippsGFpECGetSize", ippStsNoErr, status))
        return status;

    /* 5. Allocate memory for elliptic curve cryptosystem */
    std::vector<Ipp8u> pGFpECBuff(GFpECBuffSize);
    IppsGFpECState *pEC = (IppsGFpECState *)(pGFpECBuff.data());

    /* 6. Initialize the context for the cryptosystem based on a standard elliptic curve */
    status = ippsGFpECInitStd256r1(pGF, pEC);
    if (!checkStatus("ippsGFpECInitStd256r1", ippStsNoErr, status))
        return status;

    /* 7. Get the size of the scratch buffer */
    status = ippsGFpECScratchBufferSize(2, pEC, &scratchSize);
    if (!checkStatus("ippsGFpECScratchBufferSize", ippStsNoErr, status))
        return status;

    /* 8. Allocate memory for the scratch buffer */
    std::vector<Ipp8u> pScratchBuffer(scratchSize);

    /* 9. Compute the digital signature over the message digest */
    status = ippsGFpECSignDSA(bnMsgDigest, bnRegPrivate, bnEphPrivate,
                              bnR, bnS, pEC, pScratchBuffer.data());
    if (!checkStatus("ippsGFpECSignDSA", ippStsNoErr, status))
        return status;

    bool sigFlagErr;
    /* 10. Validate the generated digest by comparing it to the known one */
    sigFlagErr = (bnR == bnRref);
    sigFlagErr &= (bnS == bnSref);

    PRINT_EXAMPLE_STATUS("ippsGFpECSignDSA", "ECDSA signature", sigFlagErr)

    return status;
}
