/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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

/*F*
//    Name: ippsXMSSSetPublicKeyState
//
// Purpose: Set XMSS public key.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pRoot == NULL
//                            pSeed == NULL
//                            pState == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsNoErr             no errors
//
// Parameters:
//    OIDAlgo        id of XMSS set of parameters (algorithm)
//    pRoot          pointer to the XMSS public key root
//    pSeed          pointer to the XMSS public key seed
//    pState         pointer to the XMSS public key state
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsXMSSSetPublicKeyState, (IppsXMSSAlgo OIDAlgo,
                                              const Ipp8u* pRoot,
                                              const Ipp8u* pSeed,
                                              IppsXMSSPublicKeyState* pState))
/* clang-format on */
{
    IPP_BAD_PTR1_RET(pRoot);
    IPP_BAD_PTR1_RET(pSeed);
    IPP_BAD_PTR1_RET(pState);
    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);
    IppStatus status = ippStsNoErr;
    cpWOTSParams params;
    Ipp32s h = 0;
    status   = cp_xmss_set_params(OIDAlgo, &h, &params);
    Ipp32s n = params.n;

    pState->OIDAlgo = OIDAlgo;

    Ipp8u* ptr = (Ipp8u*)pState;

    /* allocate internal contexts */
    ptr += sizeof(IppsXMSSPublicKeyState);

    pState->pRoot = ptr;
    CopyBlock(pRoot, pState->pRoot, n);
    ptr += n;

    pState->pSeed = ptr;
    CopyBlock(pSeed, pState->pSeed, n);

    return status;
}

/*F*
//    Name: ippsXMSSSetSignatureState
//
// Purpose: Set XMSS signature.
//
// Returns:                Reason:
//    ippStsNullPtrErr        r == NULL
//                            pOTSSign == NULL
//                            pAuthPath == NULL
//                            pState == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsNoErr             no errors
//
// Parameters:
//    OIDAlgo        id of XMSS set of parameters (algorithm)
//    idx            index of XMSS leaf
//    r              pointer to the XMSS signature randomness variable
//    pOTSSign       pointer to the WOTS signature
//    pAuthPath      pointer to the XMSS authorization path
//    pState         pointer to the XMSS signature state
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsXMSSSetSignatureState, (IppsXMSSAlgo OIDAlgo,
                                              Ipp32u idx,
                                              const Ipp8u* r,
                                              const Ipp8u* pOTSSign,
                                              const Ipp8u* pAuthPath,
                                              IppsXMSSSignatureState* pState))
/* clang-format on */
{
    IPP_BAD_PTR1_RET(r);
    IPP_BAD_PTR1_RET(pOTSSign);
    IPP_BAD_PTR1_RET(pAuthPath);
    IPP_BAD_PTR1_RET(pState);

    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);
    IppStatus status = ippStsNoErr;
    cpWOTSParams params;
    Ipp32s h   = 0;
    status     = cp_xmss_set_params(OIDAlgo, &h, &params);
    Ipp32s n   = params.n;
    Ipp32s len = params.len;

    pState->idx = idx;
    Ipp8u* ptr  = (Ipp8u*)pState;

    /* allocate internal contexts */
    ptr += sizeof(IppsXMSSSignatureState);

    pState->r = ptr;
    CopyBlock(r, pState->r, n);
    ptr += n;

    pState->pOTSSign = ptr;
    CopyBlock(pOTSSign, pState->pOTSSign, len * n);
    ptr += len * n;

    pState->pAuthPath = ptr;
    CopyBlock(pAuthPath, pState->pAuthPath, h * n);

    return status;
}

/*F*
//    Name: ippsXMSSSignatureStateGetSize
//
// Purpose: Get the XMSS signature state size (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize         pointer to the size
//    OIDAlgo       id of XMSS set of parameters (algorithm)
//
*F*/

IPPFUN(IppStatus, ippsXMSSSignatureStateGetSize, (Ipp32s * pSize, IppsXMSSAlgo OIDAlgo))
{
    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);
    IppStatus status = ippStsNoErr;
    cpWOTSParams params;
    Ipp32s h   = 0;
    status     = cp_xmss_set_params(OIDAlgo, &h, &params);
    Ipp32s n   = params.n;
    Ipp32s len = params.len;

    *pSize = (Ipp32s)sizeof(IppsXMSSSignatureState) +
             /*r*/ n +
             /*pOTSSign*/ len * n +
             /*pAuthPath*/ h * n;
    return status;
}

/*F*
//    Name: ippsXMSSPublicKeyStateGetSize
//
// Purpose: Get the XMSS public key state size (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize         pointer to the size
//    OIDAlgo       id of XMSS set of parameters (algorithm)
//
*F*/

IPPFUN(IppStatus, ippsXMSSPublicKeyStateGetSize, (Ipp32s * pSize, IppsXMSSAlgo OIDAlgo))
{
    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);
    IppStatus status = ippStsNoErr;
    cpWOTSParams params;
    Ipp32s h = 0;
    status   = cp_xmss_set_params(OIDAlgo, &h, &params);
    Ipp32s n = params.n;

    *pSize = (Ipp32s)sizeof(IppsXMSSPublicKeyState) +
             /*pRoot*/ n +
             /*pSeed*/ n;
    return status;
}

/*F*
//    Name: ippsXMSSPrivateKeyStateGetSize
//
// Purpose: Get the XMSS private key state size (bytes).
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize         pointer to the size
//    OIDAlgo       id of XMSS set of parameters (algorithm)
//
*F*/

IPPFUN(IppStatus, ippsXMSSPrivateKeyStateGetSize, (Ipp32s * pSize, IppsXMSSAlgo OIDAlgo))
{
    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);
    IppStatus status = ippStsNoErr;
    cpWOTSParams params;
    Ipp32s h = 0;
    status   = cp_xmss_set_params(OIDAlgo, &h, &params);
    Ipp32s n = params.n;

    *pSize = (Ipp32s)sizeof(IppsXMSSPrivateKeyState) +
             /*pSecretSeed*/ n +
             /*pSK_PRF*/ n +
             /*pRoot*/ n +
             /*pPublicSeed*/ n;
    return status;
}

/*F*
//    Name: ippsXMSSBufferGetSize
//
// Purpose: Get the XMSS temporary buffer size (bytes) for signature verification.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsLengthErr         maxMessageLength < 1
//    ippStsLengthErr         maxMessageLength > IPP_MAX_32S - (numTempBufs + len) * n
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the size
//    maxMessageLength  maximum length of the message
//    OIDAlgo           id of XMSS set of parameters (algorithm)
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsXMSSBufferGetSize, (Ipp32s* pSize,
                                          Ipp32s maxMessageLength,
                                          IppsXMSSAlgo OIDAlgo))
/* clang-format on */
{
    IppStatus status = ippStsNoErr;

    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);
    IPP_BADARG_RET(maxMessageLength < 1, ippStsLengthErr);

    /* Set XMSS parameters */
    Ipp32s h = 0;
    cpWOTSParams params;
    status = cp_xmss_set_params(OIDAlgo, &h, &params);
    IPP_BADARG_RET((ippStsNoErr != status), status)

    const Ipp32s numTempBufs = 10;

    Ipp32s n   = params.n;
    Ipp32s len = params.len;
    // this restriction is needed to avoid overflow of Ipp32s
    IPP_BADARG_RET(maxMessageLength > (Ipp32s)(IPP_MAX_32S) - (numTempBufs + len) * n,
                   ippStsLengthErr);

    *pSize = (numTempBufs + len) * n + maxMessageLength;
    return status;
}

/*F*
//    Name: ippsXMSSVerifyBufferGetSize
//
// Purpose: Get the XMSS temporary buffer size (bytes) for signature verification.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsLengthErr         maxMessageLength < 1
//    ippStsLengthErr         maxMessageLength > IPP_MAX_32S - (numTempBufs + len) * n
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the size
//    maxMessageLength  maximum length of the message
//    OIDAlgo           id of XMSS set of parameters (algorithm)
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsXMSSVerifyBufferGetSize, (Ipp32s* pSize,
                                                Ipp32s maxMessageLength,
                                                IppsXMSSAlgo OIDAlgo))
/* clang-format on */
{
    return ippsXMSSBufferGetSize(pSize, maxMessageLength, OIDAlgo);
}

/*F*
//    Name: ippsXMSSKeyGenBufferGetSize
//
// Purpose: Get the XMSS temporary buffer size (bytes) for public and private keys generation.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the size
//    OIDAlgo           id of XMSS set of parameters (algorithm)
//
*F*/

IPPFUN(IppStatus, ippsXMSSKeyGenBufferGetSize, (Ipp32s * pSize, IppsXMSSAlgo OIDAlgo))
{
    IppStatus status = ippStsNoErr;

    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);

    /* Set XMSS parameters */
    Ipp32s h = 0;
    cpWOTSParams params;
    status = cp_xmss_set_params(OIDAlgo, &h, &params);
    IPP_BADARG_RET((ippStsNoErr != status), status)

    Ipp32s n   = params.n;
    Ipp32s len = params.len;

    *pSize = (h + 1) * (n + 1) + 2 * len * n + 7 * n + ADRS_SIZE;
    return status;
}

/*F*
//    Name: ippsXMSSSignBufferGetSize
//
// Purpose: Get the XMSS temporary buffer size (bytes) for signature creation.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsLengthErr         maxMessageLength < 1
//    ippStsLengthErr         maxMessageLength > IPP_MAX_32S - (n + 5 * n + len + key_gen_size)
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize             pointer to the size
//    maxMessageLength  maximum length of the message
//    OIDAlgo           id of XMSS set of parameters (algorithm)
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsXMSSSignBufferGetSize, (Ipp32s* pSize,
                                              Ipp32s maxMessageLength,
                                              IppsXMSSAlgo OIDAlgo))
/* clang-format on */
{
    IppStatus status = ippStsNoErr;

    IPP_BAD_PTR1_RET(pSize);
    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);
    IPP_BADARG_RET(maxMessageLength < 1, ippStsLengthErr);

    /* Set XMSS parameters */
    Ipp32s h = 0;
    cpWOTSParams params;
    status = cp_xmss_set_params(OIDAlgo, &h, &params);
    IPP_BADARG_RET((ippStsNoErr != status), status)

    Ipp32s n   = params.n;
    Ipp32s len = params.len;

    Ipp32s key_gen_size;
    status = ippsXMSSKeyGenBufferGetSize(&key_gen_size, OIDAlgo);
    IPP_BADARG_RET((ippStsNoErr != status), status)

    // this restriction is needed to avoid overflow of Ipp32s
    IPP_BADARG_RET(maxMessageLength > (Ipp32s)(IPP_MAX_32S) - (n + 5 * n + len + key_gen_size),
                   ippStsLengthErr);

    *pSize = maxMessageLength + n + 5 * n + len + key_gen_size;
    return status;
}

/*F*
//    Name: ippsXMSSInitKeyPair
//
// Purpose: Init XMSS public and private keys states.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pPrvKey == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsNoErr             no errors
//
// Parameters:
//    OIDAlgo        id of XMSS set of parameters (algorithm)
//    pPrvKey        pointer to the XMSS private key state
//    pPubKey        pointer to the XMSS public key state
//
*F*/

/* clang-format off */
IPPFUN(IppStatus, ippsXMSSInitKeyPair, (IppsXMSSAlgo OIDAlgo,
                                        IppsXMSSPrivateKeyState* pPrvKey,
                                        IppsXMSSPublicKeyState* pPubKey))
/* clang-format on */
{
    IPP_BAD_PTR1_RET(pPrvKey);
    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);
    IppStatus status = ippStsNoErr;
    cpWOTSParams params;
    Ipp32s h = 0;
    status   = cp_xmss_set_params(OIDAlgo, &h, &params);
    Ipp32s n = params.n;

    // init private key state
    pPrvKey->OIDAlgo = OIDAlgo;
    pPrvKey->idx     = 0;

    Ipp8u* ptr = (Ipp8u*)pPrvKey;

    /* allocate internal contexts */
    ptr += sizeof(IppsXMSSPrivateKeyState);

    pPrvKey->pSecretSeed = (Ipp8u*)(IPP_ALIGNED_PTR((ptr), (int)sizeof(Ipp32u)));
    ptr += n;

    pPrvKey->pSK_PRF = (Ipp8u*)(IPP_ALIGNED_PTR((ptr), (int)sizeof(Ipp32u)));
    ptr += n;

    pPrvKey->pRoot = ptr;
    ptr += n;

    pPrvKey->pPublicSeed = (Ipp8u*)(IPP_ALIGNED_PTR((ptr), (int)sizeof(Ipp32u)));

    if (pPubKey != NULL) {
        // init public key state
        pPubKey->OIDAlgo = OIDAlgo;

        ptr = (Ipp8u*)pPubKey;

        /* allocate internal contexts */
        ptr += sizeof(IppsXMSSPublicKeyState);

        pPubKey->pRoot = ptr;
        ptr += n;

        pPubKey->pSeed = (Ipp8u*)(IPP_ALIGNED_PTR((ptr), (int)sizeof(Ipp32u)));
    }

    return status;
}

/*F*
//    Name: ippsXMSSInitSignature
//
// Purpose: Init the XMSS signature state.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pState == NULL
//    ippStsBadArgErr         OIDAlgo > Max value for IppsXMSSAlgo
//    ippStsBadArgErr         OIDAlgo <= 0
//    ippStsNoErr             no errors
//
// Parameters:
//    OIDAlgo        id of XMSS set of parameters (algorithm)
//    pState         pointer to the XMSS signature state
//
*F*/

IPPFUN(IppStatus, ippsXMSSInitSignature, (IppsXMSSAlgo OIDAlgo, IppsXMSSSignatureState* pState))
{
    IPP_BAD_PTR1_RET(pState);
    IPP_BADARG_RET(OIDAlgo > XMSS_SHA2_20_512, ippStsBadArgErr);
    IPP_BADARG_RET(OIDAlgo < XMSS_SHA2_10_256, ippStsBadArgErr);
    IppStatus status = ippStsNoErr;
    cpWOTSParams params;
    Ipp32s h   = 0;
    status     = cp_xmss_set_params(OIDAlgo, &h, &params);
    Ipp32s n   = params.n;
    Ipp32s len = params.len;

    pState->idx = 0;

    Ipp8u* ptr = (Ipp8u*)pState;

    /* allocate internal contexts */
    ptr += sizeof(IppsXMSSSignatureState);

    pState->r = ptr;
    ptr += n;

    pState->pOTSSign = ptr;
    ptr += len * n;

    pState->pAuthPath = ptr;

    return status;
}
