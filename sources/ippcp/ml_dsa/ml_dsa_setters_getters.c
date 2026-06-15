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

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"

#include "pcptool.h"

#include "stateless_pqc/ml_dsa/ml_dsa.h"
#include "stateless_pqc/ml_dsa/memory_consumption.h"

/*F*
//    Name: ippsMLDSA_KeyGenBufferGetSize
//
// Purpose: Queries the size of the ippsMLDSA_KeyGen working buffer.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize     == NULL
//                            pMLDSAState == NULL
//    ippStsContextMatchErr   pMLDSAState is not initialized
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize     - output pointer with the working buffer size
//    pMLDSAState - input pointer to ML DSA state
//
*F*/
IPPFUN(IppStatus, ippsMLDSA_KeyGenBufferGetSize, (int* pSize, const IppsMLDSAState* pMLDSAState))
{
    /* Test input parameters */
    IPP_BAD_PTR2_RET(pSize, pMLDSAState);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_DSA_VALID_ID(pMLDSAState), ippStsContextMatchErr);

    *pSize = pMLDSAState->storage.keyGenCapacity;
    return ippStsNoErr;
}

/*F*
//    Name: ippsMLDSA_SignBufferGetSize
//
// Purpose: Queries the size of the ippsMLDSA_Sign working buffer.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize     == NULL
//                            pMLDSAState == NULL
//    ippStsContextMatchErr   pMLDSAState is not initialized
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize     - output pointer with the working buffer size
//    pMLDSAState - input pointer to ML DSA state
//
*F*/
IPPFUN(IppStatus, ippsMLDSA_SignBufferGetSize, (int* pSize, const IppsMLDSAState* pMLDSAState))
{
    /* Test input parameters */
    IPP_BAD_PTR2_RET(pSize, pMLDSAState);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_DSA_VALID_ID(pMLDSAState), ippStsContextMatchErr);

    *pSize = pMLDSAState->storage.signCapacity;
    return ippStsNoErr;
}

/*F*
//    Name: ippsMLDSA_VerifyBufferGetSize
//
// Purpose: Queries the size of the ippsMLDSA_Verify working buffer.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize     == NULL
//                            pMLDSAState == NULL
//    ippStsContextMatchErr   pMLDSAState is not initialized
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize     - output pointer with the working buffer size
//    pMLDSAState - input pointer to ML DSA state
//
*F*/
IPPFUN(IppStatus, ippsMLDSA_VerifyBufferGetSize, (int* pSize, const IppsMLDSAState* pMLDSAState))
{
    /* Test input parameters */
    IPP_BAD_PTR2_RET(pSize, pMLDSAState);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_DSA_VALID_ID(pMLDSAState), ippStsContextMatchErr);

    *pSize = pMLDSAState->storage.verifyCapacity;
    return ippStsNoErr;
}

/*F*
//    Name: ippsMLDSA_Verify_Mu_BufferGetSize
//
// Purpose: Queries the constant size of the ippsMLDSA_Verify_Mu working buffer.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//                            pMLDSAState == NULL
//    ippStsContextMatchErr   pMLDSAState is not initialized
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize       - output pointer with the working buffer size
//    pMLDSAState - input pointer to ML DSA state
//
*F*/
IPPFUN(IppStatus,
       ippsMLDSA_Verify_Mu_BufferGetSize,
       (int* pSize, const IppsMLDSAState* pMLDSAState))
{
    /* Test input parameters */
    IPP_BAD_PTR2_RET(pSize, pMLDSAState);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_DSA_VALID_ID(pMLDSAState), ippStsContextMatchErr);

    int verifyBytes = 0;
    IppStatus sts   = mldsaMemoryConsumption(pMLDSAState, 0, NULL, NULL, &verifyBytes);
    if (sts != ippStsNoErr) {
        return sts;
    }

    *pSize = verifyBytes;

    return ippStsNoErr;
}

/*F*
//    Name: ippsMLDSA_GetSize
//
// Purpose: Queries the size of the IppsMLDSAState.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize - output pointer with the context size
//
*F*/
IPPFUN(IppStatus, ippsMLDSA_GetSize, (int* pSize))
{
    /* Test input parameters */
    IPP_BAD_PTR1_RET(pSize);

    *pSize = (int)sizeof(IppsMLDSAState) + /* base state */
             CP_ML_ALIGNMENT;              /* alignment  */

    return ippStsNoErr;
}

/*F*
//    Name: ippsMLDSA_GetInfo
//
// Purpose: Fills IppsMLDSAInfo structure with the sizes corresponding to the given scheme type.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pInfo == NULL
//    ippStsBadArgErr         schemeType is not supported
//    ippStsNoErr             no errors
//
// Parameters:
//    pInfo      - output pointer to the ML-DSA pInfo structure
//    schemeType - input parameter specifying the scheme type
//
*F*/
IPPFUN(IppStatus, ippsMLDSA_GetInfo, (IppsMLDSAInfo * pInfo, IppsMLDSAParamSet schemeType))
{
    /* Test input pointer */
    IPP_BAD_PTR1_RET(pInfo);

    Ipp8u k, l, eta, lambda_4, omega;
    Ipp32u gamma_1;
    switch (schemeType) {

    case ML_DSA_44:
        lambda_4 = 128 / 4;
        gamma_1  = (1 << 17);
        k        = 4;
        l        = 4;
        eta      = 2;
        omega    = 80;
        break;
    case ML_DSA_65:
        lambda_4 = 192 / 4;
        gamma_1  = (1 << 19);
        k        = 6;
        l        = 5;
        eta      = 4;
        omega    = 55;
        break;
    case ML_DSA_87:
        lambda_4 = 256 / 4;
        gamma_1  = (1 << 19);
        k        = 8;
        l        = 7;
        eta      = 2;
        omega    = 75;
        break;
    default:
        return ippStsBadArgErr;
    }
    pInfo->publicKeySize  = 32 + 32 * k * CP_ML_DSA_BITLEN_Q_D;
    pInfo->privateKeySize = 32 + 32 + 64 + 32 * ((l + k) * cp_ml_bitlen(2 * eta) + CP_ML_DSA_D * k);
    pInfo->signatureSize  = lambda_4 + l * 32 * (1 + cp_ml_bitlen(gamma_1 - 1)) + omega + k;

    return ippStsNoErr;
}

/*F*
//    Name: ippsMLDSA_Init
//
// Purpose: Initializes the ML DSA context for the further ML-DSA computations.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMLDSAState == NULL
//    ippStsBadArgErr         schemeType is not supported
//    ippStsLengthErr         maxMessageLength < 1 and maxMessageLength != IPPCP_MLDSA_NO_MESSAGE
//    ippStsLengthErr         maxMessageLength > IPP_MAX_32S - locSignBytes
//    ippStsNoErr             no errors
//
// Parameters:
//    pMLDSAState - input pointer to ML DSA context
//    schemeType  - input parameter specifying the scheme type
//
*F*/
IPPFUN(IppStatus,
       ippsMLDSA_Init,
       (IppsMLDSAState * pMLDSAState, Ipp32s maxMessageLength, IppsMLDSAParamSet schemeType))
{
    /* Test input parameters */
    IPP_BAD_PTR1_RET(pMLDSAState);
    /* Set up the context id */
    CP_ML_DSA_SET_ID(pMLDSAState);

    IppStatus sts = ippStsErr;

    _cpMLDSAParams* params = &(pMLDSAState->params);
    switch (schemeType) {
    case ML_DSA_44:
        params->tau          = 39;
        params->lambda_div_4 = 128 / 4;
        params->gamma_1      = (1 << 17);
        params->gamma_2      = (CP_ML_DSA_Q - 1) / 88;
        params->k            = 4;
        params->l            = 4;
        params->eta          = 2;
        params->beta         = 78;
        params->omega        = 80;
        break;
    case ML_DSA_65:
        params->tau          = 49;
        params->lambda_div_4 = 192 / 4;
        params->gamma_1      = (1 << 19);
        params->gamma_2      = (CP_ML_DSA_Q - 1) / 32;
        params->k            = 6;
        params->l            = 5;
        params->eta          = 4;
        params->beta         = 196;
        params->omega        = 55;
        break;
    case ML_DSA_87:
        params->tau          = 60;
        params->lambda_div_4 = 256 / 4;
        params->gamma_1      = (1 << 19);
        params->gamma_2      = (CP_ML_DSA_Q - 1) / 32;
        params->k            = 8;
        params->l            = 7;
        params->eta          = 2;
        params->beta         = 120;
        params->omega        = 75;
        break;
    default:
        return ippStsBadArgErr;
    }
    /* Check msg length */
    IPP_BADARG_RET((maxMessageLength < 1) && (maxMessageLength != IPPCP_MLDSA_NO_MESSAGE),
                   ippStsLengthErr)
    if (maxMessageLength != IPPCP_MLDSA_NO_MESSAGE) {
        Ipp32s sizeof_polynom = sizeof(IppPoly);
        Ipp32s locSignBytes   = (2 * params->k + params->l) * sizeof_polynom + 3 * CP_ML_ALIGNMENT;
#if !CP_ML_MEMORY_OPTIMIZATION
        locSignBytes += params->k * params->l * sizeof_polynom + CP_ML_ALIGNMENT;
#endif // !CP_ML_MEMORY_OPTIMIZATION
        locSignBytes += 64 + 2 + 256;
        IPP_BADARG_RET(maxMessageLength > (Ipp32s)(IPP_MAX_32S)-locSignBytes, ippStsLengthErr);
    }

    /* Initialize the storage */
    int keygenBytes = 0, signBytes = 0, verifyBytes = 0;
    sts = mldsaMemoryConsumption(pMLDSAState,
                                 maxMessageLength,
                                 &keygenBytes,
                                 &signBytes,
                                 &verifyBytes);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    /* Initialize the storage */
    _cpMLDSAStorage* pStorage = &pMLDSAState->storage;
    // Actual pointer depends on the operation and will be set in the processing API
    pStorage->pStorageData   = NULL;
    pStorage->bytesCapacity  = 0;
    pStorage->bytesUsed      = 0;
    pStorage->keyGenCapacity = keygenBytes;
    pStorage->signCapacity   = signBytes;
    pStorage->verifyCapacity = verifyBytes;

    return sts;
}
