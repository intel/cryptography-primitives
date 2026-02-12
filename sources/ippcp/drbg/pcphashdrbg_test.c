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

#include "owndefs.h"
#include "owncp.h"
#include "drbg/pcphashdrbg.h"
#include "drbg/pcphashdrbg_entropy_input.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"

/*
// Hash DRBG Health Testing
*/

#define UNUSED_PARAM(x) (void)(x)

/*
// DRBG test vectors taken from NIST CAVP:
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators#DRBG
*/

/* clang-format off */
/* Test vectors to test the Instantiate function */
                                        /* entropy_input (256 bits) */
// 29e1a42709b7e84dbe50788fbad8cb609c127eec3262636a513fd9059fb8bae4
static const Ipp8u entrInput_Inst[] = { 0x29, 0xe1, 0xa4, 0x27, 0x09, 0xb7, 0xe8, 0x4d,
                                        0xbe, 0x50, 0x78, 0x8f, 0xba, 0xd8, 0xcb, 0x60,
                                        0x9c, 0x12, 0x7e, 0xec, 0x32, 0x62, 0x63, 0x6a,
                                        0x51, 0x3f, 0xd9, 0x05, 0x9f, 0xb8, 0xba, 0xe4,
                                        /* nonce (128 bits) */
// Nonce = f3a521f28dffbd97574c405b69b636ad
                                        0xf3, 0xa5, 0x21, 0xf2, 0x8d, 0xff, 0xbd, 0x97,
                                        0x57, 0x4c, 0x40, 0x5b, 0x69, 0xb6, 0x36, 0xad };

// c99a1147d8db401f4fcf763867296758e26404a30a4a9fa496a717f21f5d749b
static const Ipp8u persStr_Inst[] = { 0xc9, 0x9a, 0x11, 0x47, 0xd8, 0xdb, 0x40, 0x1f,
                                      0x4f, 0xcf, 0x76, 0x38, 0x67, 0x29, 0x67, 0x58,
                                      0xe2, 0x64, 0x04, 0xa3, 0x0a, 0x4a, 0x9f, 0xa4,
                                      0x96, 0xa7, 0x17, 0xf2, 0x1f, 0x5d, 0x74, 0x9b };

// V = 1a6f549b634059b433c5e33b6a7917cbe04952c1ac09fdb0336112fa5fb2bcb8f9bf03ee3e72e537fca69971d85f1e4e2e1ed7d2e08c08
static const Ipp8u expected_V_Inst[] = { 0x1a, 0x6f, 0x54, 0x9b, 0x63, 0x40, 0x59, 0xb4,
                                         0x33, 0xc5, 0xe3, 0x3b, 0x6a, 0x79, 0x17, 0xcb,
                                         0xe0, 0x49, 0x52, 0xc1, 0xac, 0x09, 0xfd, 0xb0,
                                         0x33, 0x61, 0x12, 0xfa, 0x5f, 0xb2, 0xbc, 0xb8,
                                         0xf9, 0xbf, 0x03, 0xee, 0x3e, 0x72, 0xe5, 0x37,
                                         0xfc, 0xa6, 0x99, 0x71, 0xd8, 0x5f, 0x1e, 0x4e,
                                         0x2e, 0x1e, 0xd7, 0xd2, 0xe0, 0x8c, 0x08 };

// C = ccefd08c206b02255de4d515034f2a437407b5b278a6d2db096f65d1b625474adc09b6b79d9b06fd2208f0a1c0dbce3f211072140ca12b
static const Ipp8u expected_C_Inst[] = { 0xcc, 0xef, 0xd0, 0x8c, 0x20, 0x6b, 0x02, 0x25,
                                         0x5d, 0xe4, 0xd5, 0x15, 0x03, 0x4f, 0x2a, 0x43,
                                         0x74, 0x07, 0xb5, 0xb2, 0x78, 0xa6, 0xd2, 0xdb,
                                         0x09, 0x6f, 0x65, 0xd1, 0xb6, 0x25, 0x47, 0x4a,
                                         0xdc, 0x09, 0xb6, 0xb7, 0x9d, 0x9b, 0x06, 0xfd,
                                         0x22, 0x08, 0xf0, 0xa1, 0xc0, 0xdb, 0xce, 0x3f,
                                         0x21, 0x10, 0x72, 0x14, 0x0c, 0xa1, 0x2b };

/* Test vectors to test the Generate Function */
// EntropyInputPR = d5266c01e10d72dd7e8a3bf717cccb8f643ca233314e3e74f106f46b090e5c73
static const Ipp8u entropyInput_Gen[] = { 0xd5, 0x26, 0x6c, 0x01, 0xe1, 0x0d, 0x72, 0xdd,
                                          0x7e, 0x8a, 0x3b, 0xf7, 0x17, 0xcc, 0xcb, 0x8f,
                                          0x64, 0x3c, 0xa2, 0x33, 0x31, 0x4e, 0x3e, 0x74,
                                          0xf1, 0x06, 0xf4, 0x6b, 0x09, 0x0e, 0x5c, 0x73 };

// AdditionalInput = 17254ea392aead0dc94992d867813497d3fd6dc7669667150afe6c28a2b89946
static const Ipp8u addtlInput_Gen[] = { 0x17, 0x25, 0x4e, 0xa3, 0x92, 0xae, 0xad, 0x0d,
                                        0xc9, 0x49, 0x92, 0xd8, 0x67, 0x81, 0x34, 0x97,
                                        0xd3, 0xfd, 0x6d, 0xc7, 0x66, 0x96, 0x67, 0x15,
                                        0x0a, 0xfe, 0x6c, 0x28, 0xa2, 0xb8, 0x99, 0x46 };

// EntropyInputPR = c7e5f03d26bdf9553338e64ba64ce5b5751b04f9c69992221495f2227b9799d0
static const Ipp8u entropyInput_Gen_2[] = { 0xc7, 0xe5, 0xf0, 0x3d, 0x26, 0xbd, 0xf9, 0x55,
                                            0x33, 0x38, 0xe6, 0x4b, 0xa6, 0x4c, 0xe5, 0xb5,
                                            0x75, 0x1b, 0x04, 0xf9, 0xc6, 0x99, 0x92, 0x22,
                                            0x14, 0x95, 0xf2, 0x22, 0x7b, 0x97, 0x99, 0xd0 };

// AdditionalInput = 157dde59ceb2c662c8665fbe623ec75873fd0c5ccce79a9f5b7098ec8ed77b67
static const Ipp8u addtlInput_Gen_2[] = { 0x15, 0x7d, 0xde, 0x59, 0xce, 0xb2, 0xc6, 0x62,
                                          0xc8, 0x66, 0x5f, 0xbe, 0x62, 0x3e, 0xc7, 0x58,
                                          0x73, 0xfd, 0x0c, 0x5c, 0xcc, 0xe7, 0x9a, 0x9f,
                                          0x5b, 0x70, 0x98, 0xec, 0x8e, 0xd7, 0x7b, 0x67 };

// ReturnedBits = e304de9ffd885cf917ead78f05939b8cf54709fc2d0c799a98b543486337204477b1060bceae2a22f7ff42b6cb4b4bc0610ae2b67558a7c54b65e45bb9f1a86981b74705b48cdbf7d8decf87868267bd948e9394aa4357f8dbbf30612a0eb5b131884c220e442d36778e8d74091d8a27c070fe690469e07f3aabeef7c629bfab
static const Ipp8u expectedOutput[] = { 0xe3, 0x04, 0xde, 0x9f, 0xfd, 0x88, 0x5c, 0xf9, 0x17, 0xea, 0xd7, 0x8f,
                                        0x05, 0x93, 0x9b, 0x8c, 0xf5, 0x47, 0x09, 0xfc, 0x2d, 0x0c, 0x79, 0x9a,
                                        0x98, 0xb5, 0x43, 0x48, 0x63, 0x37, 0x20, 0x44, 0x77, 0xb1, 0x06, 0x0b,
                                        0xce, 0xae, 0x2a, 0x22, 0xf7, 0xff, 0x42, 0xb6, 0xcb, 0x4b, 0x4b, 0xc0,
                                        0x61, 0x0a, 0xe2, 0xb6, 0x75, 0x58, 0xa7, 0xc5, 0x4b, 0x65, 0xe4, 0x5b,
                                        0xb9, 0xf1, 0xa8, 0x69, 0x81, 0xb7, 0x47, 0x05, 0xb4, 0x8c, 0xdb, 0xf7,
                                        0xd8, 0xde, 0xcf, 0x87, 0x86, 0x82, 0x67, 0xbd, 0x94, 0x8e, 0x93, 0x94,
                                        0xaa, 0x43, 0x57, 0xf8, 0xdb, 0xbf, 0x30, 0x61, 0x2a, 0x0e, 0xb5, 0xb1,
                                        0x31, 0x88, 0x4c, 0x22, 0x0e, 0x44, 0x2d, 0x36, 0x77, 0x8e, 0x8d, 0x74,
                                        0x09, 0x1d, 0x8a, 0x27, 0xc0, 0x70, 0xfe, 0x69, 0x04, 0x69, 0xe0, 0x7f,
                                        0x3a, 0xab, 0xee, 0xf7, 0xc6, 0x29, 0xbf, 0xab };

/* Test vectors to test the Reseed Function */
// EntropyInput = 6c623aea73bc8a59e28c6cd9c7c7ec8ca2e75190bd5dcae5978cf0c199c23f4f
                                              /* entropy_input (256 bits) */
static const Ipp8u entrInputInst_Reseed[] = { 0x6c, 0x62, 0x3a, 0xea, 0x73, 0xbc, 0x8a, 0x59,
                                              0xe2, 0x8c, 0x6c, 0xd9, 0xc7, 0xc7, 0xec, 0x8c,
                                              0xa2, 0xe7, 0x51, 0x90, 0xbd, 0x5d, 0xca, 0xe5,
                                              0x97, 0x8c, 0xf0, 0xc1, 0x99, 0xc2, 0x3f, 0x4f,
// Nonce = e55db067a0ed537e66886b7cda02f772
                                              /* nonce */
                                              0xe5, 0x5d, 0xb0, 0x67, 0xa0, 0xed, 0x53, 0x7e,
                                              0x66, 0x88, 0x6b, 0x7c, 0xda, 0x02, 0xf7, 0x72 };

// PersonalizationString = 1e59d798810083d1ff848e90b25c9927e3dfb55a0888b0339566a9f9ca7542dc
static const Ipp8u persStr_Reseed[] = { 0x1e, 0x59, 0xd7, 0x98, 0x81, 0x00, 0x83, 0xd1,
                                        0xff, 0x84, 0x8e, 0x90, 0xb2, 0x5c, 0x99, 0x27,
                                        0xe3, 0xdf, 0xb5, 0x5a, 0x08, 0x88, 0xb0, 0x33,
                                        0x95, 0x66, 0xa9, 0xf9, 0xca, 0x75, 0x42, 0xdc };

// EntropyInputReseed = 9ab40164744c7d00c78b4196f6f917ec33d70030a0812cd4606c5a25387568a9
static const Ipp8u entrInput_Reseed[] = { 0x9a, 0xb4, 0x01, 0x64, 0x74, 0x4c, 0x7d, 0x00,
                                          0xc7, 0x8b, 0x41, 0x96, 0xf6, 0xf9, 0x17, 0xec,
                                          0x33, 0xd7, 0x00, 0x30, 0xa0, 0x81, 0x2c, 0xd4,
                                          0x60, 0x6c, 0x5a, 0x25, 0x38, 0x75, 0x68, 0xa9 };

// AdditionalInputReseed = 4e8bead7cbba7a7bc9ae1e1617222c4139661347599950e7225d1e2faa5d57f5
static const Ipp8u addtlInput_Reseed[] = { 0x4e, 0x8b, 0xea, 0xd7, 0xcb, 0xba, 0x7a, 0x7b,
                                           0xc9, 0xae, 0x1e, 0x16, 0x17, 0x22, 0x2c, 0x41,
                                           0x39, 0x66, 0x13, 0x47, 0x59, 0x99, 0x50, 0xe7,
                                           0x22, 0x5d, 0x1e, 0x2f, 0xaa, 0x5d, 0x57, 0xf5 };

// V = 9094d0cdce1ba9157c85621622fa2b5e8523cd6d96f086519d438c87f7b0f2a310f97f5846fe5891960a91fa6ab2b037a9cd0e004d7891
static const Ipp8u expected_V_Reseed[] = { 0x90, 0x94, 0xd0, 0xcd, 0xce, 0x1b, 0xa9, 0x15,
                                           0x7c, 0x85, 0x62, 0x16, 0x22, 0xfa, 0x2b, 0x5e,
                                           0x85, 0x23, 0xcd, 0x6d, 0x96, 0xf0, 0x86, 0x51,
                                           0x9d, 0x43, 0x8c, 0x87, 0xf7, 0xb0, 0xf2, 0xa3,
                                           0x10, 0xf9, 0x7f, 0x58, 0x46, 0xfe, 0x58, 0x91,
                                           0x96, 0x0a, 0x91, 0xfa, 0x6a, 0xb2, 0xb0, 0x37,
                                           0xa9, 0xcd, 0x0e, 0x00, 0x4d, 0x78, 0x91 };

// C = d1335413e567313f7f5ad08aa9b8f524cb4fa0ece21072b0e3896a62bd21c9bc31fbf4d4ec030c8db12b3218dccfa0d8e9b63aa668e229
static const Ipp8u expected_C_Reseed[] = { 0xd1, 0x33, 0x54, 0x13, 0xe5, 0x67, 0x31, 0x3f,
                                           0x7f, 0x5a, 0xd0, 0x8a, 0xa9, 0xb8, 0xf5, 0x24,
                                           0xcb, 0x4f, 0xa0, 0xec, 0xe2, 0x10, 0x72, 0xb0,
                                           0xe3, 0x89, 0x6a, 0x62, 0xbd, 0x21, 0xc9, 0xbc,
                                           0x31, 0xfb, 0xf4, 0xd4, 0xec, 0x03, 0x0c, 0x8d,
                                           0xb1, 0x2b, 0x32, 0x18, 0xdc, 0xcf, 0xa0, 0xd8,
                                           0xe9, 0xb6, 0x3a, 0xa6, 0x68, 0xe2, 0x29 };
/* clang-format on */

static Ipp8u* pEntropyInput       = NULL;
static int entropyInputBufBitsLen = 0;

static IppStatus IPP_CALL getEntropyInputCallback(Ipp8u* entropyInput,
                                                  int* entropyBitsLen,
                                                  const int minEntropyInBits,
                                                  const int maxEntropyInBits,
                                                  const int predResistanceRequest)
{
    UNUSED_PARAM(predResistanceRequest);
    if ((entropyInputBufBitsLen < minEntropyInBits) ||
        (entropyInputBufBitsLen > maxEntropyInBits)) {
        return ippStsLengthErr;
    }
    CopyBlock(pEntropyInput, entropyInput, BITS2WORD8_SIZE(entropyInputBufBitsLen));
    *entropyBitsLen = entropyInputBufBitsLen;

    return ippStsNoErr;
}

/*
//    Name: ippsHashDRBG_InstantiateTest
//
// Purpose: Known-answer testing of the Instantiate Function of Hash DRBG
//
//  Parameters:
//    pEntrInputCtxTempBuf  Temporary buffer allocated to store the Entropy input context
//    pDrbgCtxTempBuf       Temporary buffer allocated to store the Hash DRBG state
//
//  Note: Separate buffers must be allocated for the Entropy input context and the Hash DRBG
//        state and passed to the ippsHashDRBG_InstantiateTest function. Otherwise, the current
//        state of both working buffers will be modified, leading to the generation of
//        incorrect results.
*/
IPPFUN(IppStatus,
       ippsHashDRBG_InstantiateTest,
       (IppsHashDRBG_EntropyInputCtx * pEntrInputCtxTempBuf, IppsHashDRBGState* pDrbgCtxTempBuf))
{
    const IppsHashMethod* pHashMethod = ippsHashMethod_SHA256_TT();

    IppStatus sts = ippStsNoErr;

    sts = ippsHashDRBG_Init(pHashMethod, pDrbgCtxTempBuf);
    if (ippStsNoErr != sts) {
        return sts;
    }

    int requestedSecurityStrength = 128;
    int predictionResistanceFlag  = 1;

    pEntropyInput          = (Ipp8u*)entrInput_Inst;
    entropyInputBufBitsLen = sizeof(entrInput_Inst) * 8;

    sts = ippsHashDRBG_EntropyInputCtxInit(pEntrInputCtxTempBuf,
                                           entropyInputBufBitsLen,
                                           getEntropyInputCallback);
    if (ippStsNoErr != sts) {
        return sts;
    }

    sts = ippsHashDRBG_Instantiate(requestedSecurityStrength,
                                   predictionResistanceFlag,
                                   persStr_Inst,
                                   sizeof(persStr_Inst) * 8,
                                   pEntrInputCtxTempBuf,
                                   pDrbgCtxTempBuf);
    if (ippStsNoErr != sts) {
        return sts;
    }

    Ipp8u* pV = 1 + pDrbgCtxTempBuf->V;
    for (int i = 0; i < BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN(pDrbgCtxTempBuf)); i++) {
        if (pV[i] != expected_V_Inst[i]) {
            return ippStsErr;
        }
    }
    for (int i = 0; i < BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN(pDrbgCtxTempBuf)); i++) {
        if (pDrbgCtxTempBuf->C[i] != expected_C_Inst[i]) {
            return ippStsErr;
        }
    }

    return sts;
}

/*
//    Name: ippsHashDRBG_ReseedTest
//
// Purpose: Known-answer testing of the Reseed Function of Hash DRBG
//
//  Parameters:
//    pEntrInputCtxTempBuf  Temporary buffer allocated to store the Entropy input context
//    pDrbgCtxTempBuf       Temporary buffer allocated to store the Hash DRBG state
//
//  Note: Separate buffers have to be allocated for the Entropy input context and the Hash DRBG
//        state and passed to the ippsHashDRBG_ReseedTest function. Otherwise, the current
//        state of both working buffers will be changed, which will subsequently lead to
//        the generation of incorrect results.
*/
IPPFUN(IppStatus,
       ippsHashDRBG_ReseedTest,
       (IppsHashDRBG_EntropyInputCtx * pEntrInputCtxTempBuf, IppsHashDRBGState* pDrbgCtxTempBuf))
{
    const IppsHashMethod* pHashMethod = ippsHashMethod_SHA256_TT();

    IppStatus sts = ippStsNoErr;

    sts = ippsHashDRBG_Init(pHashMethod, pDrbgCtxTempBuf);
    if (ippStsNoErr != sts) {
        return sts;
    }

    int requestedSecurityStrength = 128;
    int predictionResistanceFlag  = 1;

    pEntropyInput          = (Ipp8u*)entrInputInst_Reseed;
    entropyInputBufBitsLen = sizeof(entrInputInst_Reseed) * 8;

    sts = ippsHashDRBG_EntropyInputCtxInit(pEntrInputCtxTempBuf,
                                           entropyInputBufBitsLen,
                                           getEntropyInputCallback);
    if (ippStsNoErr != sts) {
        return sts;
    }

    sts = ippsHashDRBG_Instantiate(requestedSecurityStrength,
                                   predictionResistanceFlag,
                                   persStr_Reseed,
                                   sizeof(persStr_Reseed) * 8,
                                   pEntrInputCtxTempBuf,
                                   pDrbgCtxTempBuf);
    if (ippStsNoErr != sts) {
        return sts;
    }

    const int predictionResistanceRequest = 1;

    pEntropyInput          = (Ipp8u*)entrInput_Reseed;
    entropyInputBufBitsLen = sizeof(entrInput_Reseed) * 8;

    sts = ippsHashDRBG_Reseed(predictionResistanceRequest,
                              addtlInput_Reseed,
                              sizeof(addtlInput_Reseed) * 8,
                              pEntrInputCtxTempBuf,
                              pDrbgCtxTempBuf);

    Ipp8u* pV = 1 + pDrbgCtxTempBuf->V;
    for (int i = 0; i < BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN(pDrbgCtxTempBuf)); i++) {
        if (pV[i] != expected_V_Reseed[i]) {
            return ippStsErr;
        }
    }
    for (int i = 0; i < BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN(pDrbgCtxTempBuf)); i++) {
        if (pDrbgCtxTempBuf->C[i] != expected_C_Reseed[i]) {
            return ippStsErr;
        }
    }

    return sts;
}

/*
//    Name: ippsHashDRBG_GenTest
//
// Purpose: Known-answer testing of the Generate Function of Hash DRBG
//
//  Parameters:
//    pRandBuf              Pointer to a buffer used to store the output generated during
//                          ippsHashDRBG_Gen testing
//    nBits                 Requested number of bits to be generated
//    pEntrInputCtxTempBuf  Temporary buffer allocated to store the Entropy input context
//    pDrbgCtxTempBuf       Temporary buffer allocated to store the Hash DRBG state
//
//  Note: Separate buffers have to be allocated for the Entropy input context and the Hash DRBG
//        state and passed to the ippsHashDRBG_GenTest function. Otherwise, the current state
//        of both working buffers will be corrupted, and subsequent calls to the Generate
//        function will result in the generation of incorrect sequences of numbers.
*/
IPPFUN(IppStatus,
       ippsHashDRBG_GenTest,
       (Ipp32u * pRandBuf,
        int nBits,
        IppsHashDRBG_EntropyInputCtx* pEntrInputCtxTempBuf,
        IppsHashDRBGState* pDrbgCtxTempBuf))
{
    IPP_BADARG_RET(nBits < 1024, ippStsLengthErr);

    const IppsHashMethod* pHashMethod = ippsHashMethod_SHA256_TT();

    IppStatus sts = ippStsNoErr;

    sts = ippsHashDRBG_Init(pHashMethod, pDrbgCtxTempBuf);
    if (ippStsNoErr != sts) {
        return sts;
    }

    int requestedSecurityStrength = 128;
    int predictionResistanceFlag  = 1;

    pEntropyInput          = (Ipp8u*)entrInput_Inst;
    entropyInputBufBitsLen = sizeof(entrInput_Inst) * 8;

    sts = ippsHashDRBG_EntropyInputCtxInit(pEntrInputCtxTempBuf,
                                           entropyInputBufBitsLen,
                                           getEntropyInputCallback);
    if (ippStsNoErr != sts) {
        return sts;
    }

    sts = ippsHashDRBG_Instantiate(requestedSecurityStrength,
                                   predictionResistanceFlag,
                                   persStr_Inst,
                                   sizeof(persStr_Inst) * 8,
                                   pEntrInputCtxTempBuf,
                                   pDrbgCtxTempBuf);
    if (ippStsNoErr != sts) {
        return sts;
    }

    const int predictionResistanceRequest = 1;

    pEntropyInput          = (Ipp8u*)entropyInput_Gen;
    entropyInputBufBitsLen = sizeof(entropyInput_Gen) * 8;

    sts = ippsHashDRBG_Gen(pRandBuf,
                           nBits,
                           requestedSecurityStrength,
                           predictionResistanceRequest,
                           addtlInput_Gen,
                           sizeof(addtlInput_Gen) * 8,
                           pEntrInputCtxTempBuf,
                           pDrbgCtxTempBuf);
    if (ippStsNoErr != sts) {
        return sts;
    }

    pEntropyInput          = (Ipp8u*)entropyInput_Gen_2;
    entropyInputBufBitsLen = sizeof(entropyInput_Gen_2) * 8;

    sts = ippsHashDRBG_Gen(pRandBuf,
                           nBits,
                           requestedSecurityStrength,
                           predictionResistanceRequest,
                           addtlInput_Gen_2,
                           sizeof(addtlInput_Gen_2) * 8,
                           pEntrInputCtxTempBuf,
                           pDrbgCtxTempBuf);
    if (ippStsNoErr != sts) {
        return sts;
    }

    Ipp8u* pRandTemp = (Ipp8u*)pRandBuf;

    for (int i = 0; i < BITS2WORD8_SIZE(nBits); i++) {
        if (pRandTemp[i] != expectedOutput[i]) {
            return ippStsErr;
        }
    }

    return sts;
}
