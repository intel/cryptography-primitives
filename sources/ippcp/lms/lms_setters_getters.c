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
#include "lms_internal/lms.h"

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

IPPFUN(IppStatus, ippsLMSBufferGetSize, (Ipp32s* pSize, Ipp32s maxMessageLength, const IppsLMSAlgoType lmsType))
{
    IppStatus ippcpSts = ippStsNoErr;

    /* Input parameters check */
    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo > LMS_SHA256_M24_H25,  ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo < LMS_SHA256_M32_H5,   ippStsBadArgErr);


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
    IPP_BADARG_RET(maxMessageLength  >  (Ipp32s)((IPP_MAX_32S) - (CP_PK_I_BYTESIZE + 4 +   2    + lmotsParams.n)),
                   ippStsLengthErr);

    /* Calculate the maximum Set LMOTS and LMS parameters */
                      //    pubKey->I   ||  q  ||  D_MESG  ||          C        ||            pMsg
    Ipp32u lenBufQ    = CP_PK_I_BYTESIZE +  4   +     2     +    lmotsParams.n   + (Ipp32u)maxMessageLength;
                      //    pubKey->I   ||  q  ||  i  || j ||     Y[i]
    Ipp32u lenBufTmp  = CP_PK_I_BYTESIZE +  4  +   2  +  1  + lmotsParams.n;
                      //    pubKey->I   || node_num || D_LEAF ||      Kc
    Ipp32u lenBufTc   = CP_PK_I_BYTESIZE +     4     +    2    + lmotsParams.n;
                      //    pubKey->I   || node_num/2 || D_INTR ||    path[i]   ||     tmp
    Ipp32u lenBufIntr = CP_PK_I_BYTESIZE +      4      +    2    + lmotsParams.n + lmotsParams.n;

    *pSize = (Ipp32s)IPP_MAX(IPP_MAX(IPP_MAX(lenBufQ, lenBufTmp), lenBufTc), lenBufIntr);

    return ippcpSts;
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

IPPFUN(IppStatus, ippsLMSSignatureStateGetSize, (Ipp32s* pSize, const IppsLMSAlgoType lmsType))
{
    IppStatus ippcpSts = ippStsNoErr;

    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo > LMS_SHA256_M24_H25,  ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo < LMS_SHA256_M32_H5,   ippStsBadArgErr);

    /* Set LMOTS and LMS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    *pSize = (Ipp32s)sizeof(IppsLMSSignatureState)  +
             (Ipp32s)(lmotsParams.n * lmsParams.h)  + /*_pAuthPath*/
             (Ipp32s)lmotsParams.n                  + /* C */
             (Ipp32s)(lmotsParams.n * lmotsParams.p); /* Y */

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
IPPFUN(IppStatus, ippsLMSPublicKeyStateGetSize, (Ipp32s* pSize, const IppsLMSAlgoType lmsType))
{
    IppStatus ippcpSts = ippStsNoErr;

    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo > LMS_SHA256_M24_H25,  ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo < LMS_SHA256_M32_H5,   ippStsBadArgErr);

    /* Set LMS parameters */
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    *pSize = (Ipp32s)sizeof(IppsLMSPublicKeyState) +
             (Ipp32s)lmsParams.m; /* T1 */

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
IPPFUN(IppStatus, ippsLMSSetPublicKeyState, (const IppsLMSAlgoType lmsType,
                                             const Ipp8u* pI, const Ipp8u* pK,
                                             IppsLMSPublicKeyState* pState))
{
    IppStatus ippcpSts = ippStsNoErr;

    IPP_BAD_PTR3_RET(pI, pK, pState);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo > LMS_SHA256_M24_H25,  ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo < LMS_SHA256_M32_H5,   ippStsBadArgErr);

    /* Set context id to prevent its copying */
    CP_LMS_SET_CTX_ID(pState);

    /* Set LMS parameters */
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    /* Fill in the structure */
    pState->lmsOIDAlgo = lmsType.lmsOIDAlgo;
    pState->lmotsOIDAlgo = lmsType.lmotsOIDAlgo;
    CopyBlock(pI, pState->I, CP_PK_I_BYTESIZE);
    // Set pointer to T1 right to the end of the context
    pState->T1 = (Ipp8u*)pState+sizeof(IppsLMSPublicKeyState);
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

IPPFUN(IppStatus, ippsLMSSetSignatureState, (const IppsLMSAlgoType lmsType,
                                             Ipp32u q,
                                             const Ipp8u* pC,
                                             const Ipp8u* pY,
                                             const Ipp8u* pAuthPath,
                                             IppsLMSSignatureState* pState))
{
    IPP_BAD_PTR4_RET(pC, pY, pAuthPath, pState);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo > LMOTS_SHA256_N24_W8, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmotsOIDAlgo < LMOTS_SHA256_N32_W1, ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo > LMS_SHA256_M24_H25,  ippStsBadArgErr);
    IPP_BADARG_RET(lmsType.lmsOIDAlgo < LMS_SHA256_M32_H5,   ippStsBadArgErr);

    IppStatus ippcpSts = ippStsNoErr;

    /* Set LMOTS and LMS parameters */
    cpLMOTSParams lmotsParams;
    ippcpSts = setLMOTSParams(lmsType.lmotsOIDAlgo, &lmotsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)
    cpLMSParams lmsParams;
    ippcpSts = setLMSParams(lmsType.lmsOIDAlgo, &lmsParams);
    IPP_BADARG_RET((ippStsNoErr != ippcpSts), ippcpSts)

    /* Set context id to prevent its copying */
    CP_LMS_SET_CTX_ID(pState);

    /* Check q value before set */
    Ipp32u qLimit = 1 << lmsParams.h;
    IPP_BADARG_RET(q >= qLimit,   ippStsBadArgErr);

    pState->_q = q;
    pState->_lmsOIDAlgo = lmsType.lmsOIDAlgo;

    _cpLMOTSSignatureState* locLMOTSSig = &(pState->_lmotsSig);
    locLMOTSSig->_lmotsOIDAlgo = lmsType.lmotsOIDAlgo;

    // Copy auth path data
    Ipp32s authPathSize = (Ipp32s)(lmsParams.h * lmotsParams.n);
    pState->_pAuthPath = (Ipp8u*)pState+sizeof(IppsLMSSignatureState);
    CopyBlock(pAuthPath, pState->_pAuthPath, authPathSize);

    // Copy C data
    Ipp32s cSize = (Ipp32s)lmotsParams.n;
    locLMOTSSig->pC = (Ipp8u*)pState->_pAuthPath+authPathSize;
    CopyBlock(pC, locLMOTSSig->pC, cSize);

    // Copy Y data
    Ipp32s ySize = (Ipp32s)(lmotsParams.n * lmotsParams.p);
    locLMOTSSig->pY = (Ipp8u*)pState->_pAuthPath+authPathSize+cSize;
    CopyBlock(pY, locLMOTSSig->pY, ySize);

    return ippcpSts;
}
