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

#include "owndefs.h"
#include "stateful_sig/lms_internal/lms.h"

/*F*
//    Name: ippsLMSBufferGetSize
//
// Purpose: Get the LMS temporary buffer size (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//                            lmsType.lmsOIDAlgo   > LMS_SHA256_M24_H25
//                            lmsType.lmsOIDAlgo   < LMS_SHA256_M32_H5
//    ippStsLengthErr         maxMessageLength < 1
//                            maxMessageLength > (Ipp32s)(IPP_MAX_32S) -
//                            - (byteSizeI + 4(q byteSize) + 2(D_MESG byteSize) + n(C byteSize))
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the work buffer's byte size
//    maxMessageLength  maximum length of the processing message
//    lmsType           structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsLMSBufferGetSize, (Ipp32s* pSize,
                                         Ipp32s maxMessageLength,
                                         const IppsLMSAlgoType lmsType))
/* clang-format on */
{
    IppStatus ippcpSts = ippStsErr;

    /* Input parameters check */
    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);

    /* Set LMOTS and LMS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    /* Check message length */
    IPP_BADARG_RET(maxMessageLength < 1, ippStsLengthErr);
    // this restriction is needed to avoid overflow of Ipp32s
    // maxMessageLength must be less than    IPP_MAX_32S       - (CP_PK_I_BYTESIZE + q + D_MESG +      C       )
    IPP_BADARG_RET(maxMessageLength >
                       (Ipp32s)((IPP_MAX_32S) - (CP_PK_I_BYTESIZE + 4 + 2 + lmotsParams.n)),
                   ippStsLengthErr);
    /* clang-format off */
    /* Calculate the maximum Set LMOTS and LMS parameters */
                      //    pubKey->I   ||  q  ||  D_MESG  ||          C        ||            pMsg
    Ipp32u lenBufQ    = CP_PK_I_BYTESIZE +  4   +     2     +    lmotsParams.n   + (Ipp32u)maxMessageLength;
                     //    pubKey->I   ||  q  ||  i  || j ||     Y[i]
    Ipp32u lenBufTmp  = CP_PK_I_BYTESIZE +  4  +   2  +  1  + lmotsParams.n;
                      //    pubKey->I   || node_num || D_LEAF ||      Kc
    Ipp32u lenBufTc   = CP_PK_I_BYTESIZE +     4     +    2    + lmotsParams.n;
                      //    pubKey->I   || node_num/2 || D_INTR ||    path[i]   ||     tmp
    Ipp32u lenBufIntr = CP_PK_I_BYTESIZE +      4      +    2    + lmsParams.m + lmsParams.m;
    Ipp32u lenBufZ    = (lmotsParams.p + 1) * lmotsParams.n;
    // lenBufQZ = lenBufQ + (lenBufZ  - /* shift to reuse Q */ (Ipp32u)maxMessageLength + 1);
    Ipp32u lenBufQZ = CP_PK_I_BYTESIZE + 4 + 2 + lmotsParams.n + lenBufZ + 1;
    /* clang-format on */

    *pSize = (Ipp32s)IPP_MAX(IPP_MAX(IPP_MAX(IPP_MAX(lenBufQZ, lenBufQ), lenBufTmp), lenBufTc),
                             lenBufIntr);

    return ippcpSts;
}

/*F*
//    Name: ippsLMSVerifyBufferGetSize
//
// Purpose: Get the size of temporary buffer required for LMS verification (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//                            lmsType.lmsOIDAlgo   > LMS_SHA256_M24_H25
//                            lmsType.lmsOIDAlgo   < LMS_SHA256_M32_H5
//    ippStsLengthErr         maxMessageLength < 1
//                            maxMessageLength > (Ipp32s)(IPP_MAX_32S) -
//                            - (byteSizeI + 4(q byteSize) + 2(D_MESG byteSize) + n(C byteSize))
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the work buffer's byte size
//    maxMessageLength  maximum length of the processing message
//    lmsType           structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsLMSVerifyBufferGetSize, (Ipp32s* pSize,
                                               Ipp32s maxMessageLength,
                                               const IppsLMSAlgoType lmsType))
/* clang-format on */
{
    return ippsLMSBufferGetSize(pSize, maxMessageLength, lmsType);
}

/*F*
//    Name: ippsLMSSignatureStateGetSize
//
// Purpose: Get the LMS signature state size (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//                            lmsType.lmsOIDAlgo   > LMS_SHA256_M24_H25
//                            lmsType.lmsOIDAlgo   < LMS_SHA256_M32_H5
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize         pointer to the size
//    lmsType       structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//
*F*/

IPPFUN(IppStatus, ippsLMSSignatureStateGetSize, (Ipp32s * pSize, const IppsLMSAlgoType lmsType))
{
    IppStatus ippcpSts = ippStsErr;

    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);

    /* Set LMOTS and LMS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    Ipp32s lmots_sign_size = (Ipp32s)(lmotsParams.n                              // C
                                      + lmotsParams.n * lmotsParams.p)           // Y
                             + CP_LMS_ALIGNMENT;
    *pSize = (Ipp32s)(sizeof(IppsLMSSignatureState) + lmsParams.m * lmsParams.h) // path
             + lmots_sign_size;                                                  // lmots_sig

    return ippcpSts;
}

/*F*
//    Name: ippsLMSPublicKeyStateGetSize
//
// Purpose: Provides the LMS public key state size (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//                            lmsType.lmsOIDAlgo   > LMS_SHA256_M24_H25
//                            lmsType.lmsOIDAlgo   < LMS_SHA256_M32_H5
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the size
//    lmsType           structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//
*F*/
IPPFUN(IppStatus, ippsLMSPublicKeyStateGetSize, (Ipp32s * pSize, const IppsLMSAlgoType lmsType))
{
    IppStatus ippcpSts = ippStsErr;

    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);

    /* Set LMS parameters */
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    *pSize = (Ipp32s)sizeof(IppsLMSPublicKeyState) +
             /* T1 */ (Ipp32s)lmsParams.m;

    return ippcpSts;
}

/*F*
//    Name: ippsLMSSetPublicKeyState
//
// Purpose: Set LMS public key.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pI == NULL
//                            pK == NULL
//                            pState == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//                            lmsType.lmsOIDAlgo   > LMS_SHA256_M24_H25
//                            lmsType.lmsOIDAlgo   < LMS_SHA256_M32_H5
//    ippStsNoErr             no errors
//
// Parameters:
//    lmsType         structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//    pI              pointer to the LMS private key identifier
//    pK              pointer to the LMS public key
//    pState          pointer to the LMS public key state
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsLMSSetPublicKeyState, (const IppsLMSAlgoType lmsType,
                                             const Ipp8u* pI,
                                             const Ipp8u* pK,
                                             IppsLMSPublicKeyState* pState))
/* clang-format on */
{
    IppStatus ippcpSts = ippStsErr;

    IPP_BAD_PTR3_RET(pI, pK, pState);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);

    /* Set context id to prevent its copying */
    CP_LMS_SET_PUB_KEY_CTX_ID(pState);

    /* Set LMS parameters */
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    /* Fill in the structure */
    pState->lmsOIDAlgo   = lmsType.lmsOIDAlgo;
    pState->lmotsOIDAlgo = lmsType.lmotsOIDAlgo;
    CopyBlock(pI, pState->I, CP_PK_I_BYTESIZE);
    // Set pointer to T1 right to the end of the context
    pState->T1 = (Ipp8u*)pState + sizeof(IppsLMSPublicKeyState);
    CopyBlock(pK, pState->T1, (cpSize)lmsParams.m);

    return ippcpSts;
}

/*F*
//    Name: ippsLMSSetSignatureState
//
// Purpose: Set LMS signature.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pC == NULL
//                            pY == NULL
//                            pAuthPath == NULL
//                            pState == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//                            lmsType.lmsOIDAlgo   > LMS_SHA256_M24_H25
//                            lmsType.lmsOIDAlgo   < LMS_SHA256_M32_H5
//                            q is incorrect
//    ippStsNoErr             no errors
//
// Parameters:
//    lmsType        structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//    q              index of LMS leaf
//    pC             pointer to the C LM-OTS value
//    pY             pointer to the y LM-OTS value
//    pAuthPath      pointer to the LMS authorization path
//    pState         pointer to the LMS signature state
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsLMSSetSignatureState, (const IppsLMSAlgoType lmsType,
                                             Ipp32u q,
                                             const Ipp8u* pC,
                                             const Ipp8u* pY,
                                             const Ipp8u* pAuthPath,
                                             IppsLMSSignatureState* pState))
/* clang-format on */
{
    IPP_BAD_PTR4_RET(pC, pY, pAuthPath, pState);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);

    IppStatus ippcpSts = ippStsErr;

    /* Set LMOTS and LMS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    /* Set context id to prevent its copying */
    CP_LMS_SET_SIGN_CTX_ID(pState);

    /* Check q value before set */
    Ipp32u qLimit = 1 << lmsParams.h;
    IPP_BADARG_RET(q >= qLimit, ippStsBadArgErr);

    pState->_q          = q;
    pState->_lmsOIDAlgo = lmsType.lmsOIDAlgo;

    _cpLMOTSSignatureState* locLMOTSSig = &(pState->_lmotsSig);
    locLMOTSSig->_lmotsOIDAlgo          = lmsType.lmotsOIDAlgo;

    // Copy auth path data
    Ipp32s authPathSize = (Ipp32s)(lmsParams.h * lmsParams.m);
    pState->_pAuthPath  = (Ipp8u*)pState + sizeof(IppsLMSSignatureState);
    CopyBlock(pAuthPath, pState->_pAuthPath, authPathSize);

    // Copy C data
    Ipp32s cSize    = (Ipp32s)lmotsParams.n;
    locLMOTSSig->pC = (Ipp8u*)pState->_pAuthPath + authPathSize;
    CopyBlock(pC, locLMOTSSig->pC, cSize);

    // Copy Y data
    Ipp32s ySize    = (Ipp32s)(lmotsParams.n * lmotsParams.p);
    locLMOTSSig->pY = (Ipp8u*)pState->_pAuthPath + authPathSize + cSize;
    CopyBlock(pY, locLMOTSSig->pY, ySize);

    return ippcpSts;
}

/*F*
//    Name: ippsLMSKeyGenBufferGetSize
//
// Purpose: Get the LMS temporary buffer size needed for ippsLMSKeyGen (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//                            lmsType.lmsOIDAlgo   > LMS_SHA256_M24_H25
//                            lmsType.lmsOIDAlgo   < LMS_SHA256_M32_H5
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the work buffer's byte size
//    lmsType           structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//
*F*/

IPPFUN(IppStatus, ippsLMSKeyGenBufferGetSize, (Ipp32s * pSize, const IppsLMSAlgoType lmsType))
{
    IppStatus ippcpSts = ippStsErr;

    /* Input parameters check */
    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);

    /* Set LMOTS and LMS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    Ipp32u n = lmotsParams.n;
    Ipp32u m = lmsParams.m;
    Ipp32u p = lmotsParams.p;
    Ipp32u h = lmsParams.h;

    /* H_tree input: I || u32str(r) || u16str(D_INTR) || left(m) || right(m) */
    Ipp32u lenHTreeBuf = CP_PK_I_BYTESIZE + 4 + 2 + m + m;
    /* Tree stack (h nodes of m bytes) + heights array */
    Ipp32u lenStack = (h + 1) + h * m;
    /* Node scratch: holds n-byte OTS pubkey then m-byte tree hash */
    Ipp32u lenNode = CP_LMS_MAX_HASH_BYTESIZE;
    /* cp_lms_OTS_genPK workspace: I_q header         +       max(m,n)           + sk entries */
    Ipp32u lenOtsGenPK = CP_PK_I_BYTESIZE + 4 + 2 + 1 + CP_LMS_MAX_HASH_BYTESIZE + n * p;

    *pSize = (Ipp32s)(lenHTreeBuf + lenStack + lenNode + lenOtsGenPK);

    return ippcpSts;
}

/*F*
//    Name: ippsLMSSignBufferGetSize
//
// Purpose: Get the LMS temporary buffer size needed for ippsLMSSign (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//    ippStsLengthErr         maxMessageLength < 1
//                            maxMessageLength > (Ipp32s)(IPP_MAX_32S) -
//                            - (byteSizeI + 4(q byteSize) + 2(D_MESG byteSize) + n(C byteSize))
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the work buffer's byte size
//    maxMessageLength  maximum length of the processing message
//    lmsType           structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//
*F*/

IPPFUN(IppStatus,
       ippsLMSSignBufferGetSize,
       (Ipp32s * pSize, Ipp32s maxMessageLength, const IppsLMSAlgoType lmsType))
{
    IppStatus ippcpSts = ippStsErr;

    /* Input parameters check */
    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);

    /* Set LMOTS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    Ipp32u n                 = lmotsParams.n; // LMOTS n
    Ipp32s key_gen_temp_size = 0;

    /* Check message length */
    IPP_BADARG_RET(maxMessageLength < 1, ippStsLengthErr);
    // this restriction is needed to avoid overflow of Ipp32s
    // maxMessageLength must be less than       IPP_MAX_32S  - (CP_PK_I_BYTESIZE + q + D_MESG + C)
    IPP_BADARG_RET(maxMessageLength > (Ipp32s)((IPP_MAX_32S) - (CP_PK_I_BYTESIZE + 4 + 2 + n)),
                   ippStsLengthErr);

    ippcpSts = ippsLMSKeyGenBufferGetSize(&key_gen_temp_size, lmsType);

    Ipp32u lenOtsSign = CP_PK_I_BYTESIZE + 4 + 2 + n +
                        IPP_MAX((Ipp32u)maxMessageLength, 1 + CP_LMS_MAX_HASH_BYTESIZE);
    *pSize = (Ipp32s)(IPP_MAX(lenOtsSign, (Ipp32u)key_gen_temp_size));
    return ippcpSts;
}

/*F*
//    Name: ippsLMSPrivateKeyStateGetSize
//
// Purpose: Provides the LMS private key state size (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//    ippStsLengthErr         extraBufSize < 0
//    ippStsSizeWrn           extraBufSize % lmsParams.m != 0
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the size
//    lmsType           structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//    extraBufSize      size of the extra buffer for the private key
//
*F*/

IPPFUN(IppStatus,
       ippsLMSPrivateKeyStateGetSize,
       (Ipp32s * pSize, const IppsLMSAlgoType lmsType, Ipp32s extraBufSize))
{
    IppStatus ippcpSts = ippStsErr;

    /* Input parameters check */
    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(extraBufSize < 0, ippStsLengthErr);

    /* Set LMOTS and LMS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    // Data are kept in the extra buffer by chunks equal lmsParams.m.
    // There is no sense to keep space for less than lmsParams.m bytes
    IPP_BADARG_RET((extraBufSize % (Ipp32s)lmsParams.m) != 0, ippStsSizeWrn);
    // rounding to lmsParams.m
    extraBufSize = (extraBufSize / (Ipp32s)lmsParams.m) * (Ipp32s)lmsParams.m;

    *pSize = (Ipp32s)(sizeof(IppsLMSPrivateKeyState) + lmsParams.m + CP_PK_I_BYTESIZE) +
             extraBufSize + 2 * CP_LMS_ALIGNMENT;

    return ippcpSts;
}

/*F*
//    Name: ippsLMSSetPrivateKeyState
//
// Purpose: Set LMS private key's type, otstype, q, extrabufSize, secret seed, pI and extra buf to data read from file.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSecretSeed == NULL
//                            pI == NULL
//                            pState == NULL
//                            pExtraBuf == NULL (when extraBufSize > 0)
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8
//                            lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1
//                            lmsType.lmsOIDAlgo   > LMS_SHA256_M24_H25
//                            lmsType.lmsOIDAlgo   < LMS_SHA256_M32_H5
//                            q is out of valid range
//    ippStsLengthErr         extraBufSize < 0
//    ippStsNoErr             no errors
//
// Parameters:
//    lmsType         structure with LMS parameters lmotsOIDAlgo and lmsOIDAlgo
//    q               leaf number (signature counter)
//    pSecretSeed     pointer to the LMS private key secret seed
//    pI              pointer to the LMS private key identifier
//    pExtraBuf       pointer to extra buffer data (can be NULL if extraBufSize is 0)
//    extraBufSize    size of extra buffer data
//    pState          pointer to the LMS private key state
//
*F*/
/* clang-format off */
IPPFUN(IppStatus, ippsLMSSetPrivateKeyState, (const IppsLMSAlgoType lmsType,
                                              const Ipp32u q,
                                              const Ipp8u* pSecretSeed,
                                              const Ipp8u* pI,
                                              const Ipp8u* pExtraBuf,
                                              const Ipp32s extraBufSize,
                                              IppsLMSPrivateKeyState* pState))
/* clang-format on */
{
    IPP_BAD_PTR3_RET(pSecretSeed, pI, pState);

    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(extraBufSize < 0, ippStsLengthErr);
    IPP_BADARG_RET((extraBufSize > 0) && (NULL == pExtraBuf), ippStsNullPtrErr);

    IppStatus ippcpSts = ippStsErr;

    /* Set LMS and LMOTS parameters */
    cpLMSParams lmsParams;
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    /* Validate q parameter - should be less than 2^h */
    IPP_BADARG_RET(q >= (1u << lmsParams.h), ippStsBadArgErr);

    /* Set context id to prevent its copying */
    CP_LMS_SET_PRIV_KEY_CTX_ID(pState);
    /* Set algorithm types */
    pState->lmsOIDAlgo   = lmsType.lmsOIDAlgo;
    pState->lmotsOIDAlgo = lmsType.lmotsOIDAlgo;

    /* Set q (signature counter) */
    pState->q = q;

    Ipp8u* ptr = (Ipp8u*)pState;

    /* allocate internal contexts */
    ptr += sizeof(IppsLMSPrivateKeyState);

    pState->pSecretSeed = (Ipp8u*)(IPP_ALIGNED_PTR((ptr), CP_LMS_ALIGNMENT));
    /* Copy secret seed */
    CopyBlock(pSecretSeed, pState->pSecretSeed, (cpSize)lmsParams.m);
    ptr += lmsParams.m;

    pState->pI = (Ipp8u*)(IPP_ALIGNED_PTR((ptr), CP_LMS_ALIGNMENT));
    /* Copy identifier */
    CopyBlock(pI, pState->pI, CP_PK_I_BYTESIZE);
    ptr += CP_PK_I_BYTESIZE;

    pState->pExtraBuf = ptr;
    /* Rounding to lmsParams.m and set */
    pState->extraBufSize = (extraBufSize / (Ipp32s)lmsParams.m) * (Ipp32s)lmsParams.m;
    /* Copy extra buffer data if present */
    if (pState->extraBufSize > 0 && pExtraBuf != NULL) {
        CopyBlock(pExtraBuf, pState->pExtraBuf, pState->extraBufSize);
    }

    return ippStsNoErr;
}

/*F*
//    Name: ippsLMSInitKeyPair
//
// Purpose: Init LMS public and private keys states.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pPrvKey == NULL or pPubKey == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > Max value for IppsLMOTSAlgo
//                            lmsType.lmotsOIDAlgo < Min value for IppsLMOTSAlgo
//                            lmsType.lmsOIDAlgo > Max value for IppsLMSAlgo
//                            lmsType.lmsOIDAlgo < Min value for IppsLMSAlgo
//    ippStsLengthErr         extraBufSize < 0
//    ippStsNoErr             no errors
//
// Parameters:
//    lmsType        id of LMS set of parameters (algorithm)
//    pPrvKey        pointer to the LMS private key state
//    pPubKey        pointer to the LMS public key state
//    extraBufSize   size of the extra buffer for the private key (bytes)
//
*F*/

IPPFUN(IppStatus,
       ippsLMSInitKeyPair,
       (const IppsLMSAlgoType lmsType,
        Ipp32s extraBufSize,
        IppsLMSPrivateKeyState* pPrvKey,
        IppsLMSPublicKeyState* pPubKey))
{
    IppStatus ippcpSts = ippStsErr;
    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(extraBufSize < 0, ippStsLengthErr);

    /* Input parameters check */
    IPP_BAD_PTR2_RET(pPrvKey, pPubKey);

    /* Set LMS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    CP_LMS_SET_PRIV_KEY_CTX_ID(pPrvKey);
    pPrvKey->lmsOIDAlgo   = lmsType.lmsOIDAlgo;
    pPrvKey->lmotsOIDAlgo = lmsType.lmotsOIDAlgo;

    Ipp8u* ptr = (Ipp8u*)pPrvKey;

    /* allocate internal contexts */
    ptr += sizeof(IppsLMSPrivateKeyState);

    pPrvKey->pSecretSeed = (Ipp8u*)(IPP_ALIGNED_PTR((ptr), CP_LMS_ALIGNMENT));
    ptr += lmsParams.m;

    pPrvKey->pI = (Ipp8u*)(IPP_ALIGNED_PTR((ptr), CP_LMS_ALIGNMENT));
    ptr += CP_PK_I_BYTESIZE;

    pPrvKey->pExtraBuf = ptr;
    // rounding to lmsParams.m
    extraBufSize          = (extraBufSize / (Ipp32s)lmsParams.m) * (Ipp32s)lmsParams.m;
    pPrvKey->extraBufSize = extraBufSize;

    CP_LMS_SET_PUB_KEY_CTX_ID(pPubKey);
    pPubKey->lmsOIDAlgo   = lmsType.lmsOIDAlgo;
    pPubKey->lmotsOIDAlgo = lmsType.lmotsOIDAlgo;

    ptr = (Ipp8u*)pPubKey;
    ptr += sizeof(IppsLMSPublicKeyState);

    pPubKey->T1 = ptr;

    return ippcpSts;
}

/*F*
//    Name: ippsLMSInitSignature
//
// Purpose: Init the LMS signature state.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSign == NULL
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo > Max value for IppsLMOTSAlgo
//    ippStsBadArgErr         lmsType.lmotsOIDAlgo < Min value for IppsLMOTSAlgo
//    ippStsBadArgErr         lmsType.lmsOIDAlgo > Max value for IppsLMSAlgo
//    ippStsBadArgErr         lmsType.lmsOIDAlgo < Min value for IppsLMSAlgo
//    ippStsNoErr             no errors
//
// Parameters:
//    lmsType        id of LMS set of parameters (algorithm)
//    pSign          pointer to the LMS signature state
//
*F*/

IPPFUN(IppStatus,
       ippsLMSInitSignature,
       (const IppsLMSAlgoType lmsType, IppsLMSSignatureState* pSign))
{
    IppStatus ippcpSts = ippStsErr;
    IPP_BADARG_RET(lmsType.lmsOIDAlgo >= LMS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo <= LMS_MIN, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo >= LMOTS_MAX, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo <= LMOTS_MIN, ippStsBadArgErr);

    IPP_BAD_PTR1_RET(pSign);

    /* Set LMOTS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    CP_LMS_SET_SIGN_CTX_ID(pSign);
    pSign->_lmsOIDAlgo = lmsType.lmsOIDAlgo;
    pSign->_q          = 0;

    Ipp8u* ptr = (Ipp8u*)pSign;

    /* allocate internal contexts */
    ptr += sizeof(IppsLMSSignatureState);

    pSign->_lmotsSig._lmotsOIDAlgo = lmsType.lmotsOIDAlgo;
    pSign->_lmotsSig.pC            = (Ipp8u*)(IPP_ALIGNED_PTR((ptr), CP_LMS_ALIGNMENT));
    ptr += lmotsParams.n;

    pSign->_lmotsSig.pY = ptr;
    ptr += lmotsParams.n * lmotsParams.p;

    pSign->_pAuthPath = ptr;

    return ippcpSts;
}
