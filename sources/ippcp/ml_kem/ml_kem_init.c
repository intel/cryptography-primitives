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
#include "ml_kem_internal/ml_kem.h"
#include "ml_kem_internal/memory_consumption.h"

/*F*
//    Name: ippsMLKEM_Init
//
// Purpose: Initializes the ML KEM context for the further ML-KEM computations.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pMLKEMCtx == NULL
//    ippStsBadArgErr         schemeType is not supported
//    ippStsNoErr             no errors
//
// Parameters:
//    pMLKEMCtx  - input pointer to ML KEM context
//    schemeType - input parameter specifying the scheme type
//
*F*/
IPPFUN(IppStatus, ippsMLKEM_Init, (IppsMLKEMState * pMLKEMCtx, IppsMLKEMParamSet schemeType))
{
    /* Test input parameters */
    IPP_BAD_PTR1_RET(pMLKEMCtx);
    /* Set up the context id */
    CP_ML_KEM_SET_ID(pMLKEMCtx);

    IppStatus sts = ippStsNoErr;

    _cpMLKEMParams* params = &(pMLKEMCtx->params);
    params->n              = CP_ML_KEM_N;
    params->q              = CP_ML_KEM_Q;
    params->eta2           = CP_ML_KEM_ETA2;
    switch (schemeType) {
    case IPPCP_ML_KEM_512:
        params->k    = 2;
        params->eta1 = 3;
        params->d_u  = 10;
        params->d_v  = 4;
        break;
    case IPPCP_ML_KEM_768:
        params->k    = 3;
        params->eta1 = 2;
        params->d_u  = 10;
        params->d_v  = 4;
        break;
    case IPPCP_ML_KEM_1024:
        params->k    = 4;
        params->eta1 = 2;
        params->d_u  = 11;
        params->d_v  = 5;
        break;
    default:
        return ippStsBadArgErr;
    }

    /* Put pointer into the end of the ctx */
    pMLKEMCtx->pA =
        (Ipp16u*)IPP_ALIGNED_PTR((Ipp8u*)pMLKEMCtx + sizeof(IppsMLKEMState), CP_ML_KEM_ALIGNMENT);

    /* Initialize the storage */
    int keygenBytes = 0, encapsBytes = 0, decapsBytes = 0;
    sts = mlkemMemoryConsumption(pMLKEMCtx, &keygenBytes, &encapsBytes, &decapsBytes);

    /* Initialize the storage */
    _cpMLKEMStorage* pStorage = &pMLKEMCtx->storage;
    // Actual pointer depends on the operation and will be set in the processing API
    pStorage->pStorageData   = NULL;
    pStorage->bytesCapacity  = 0;
    pStorage->bytesUsed      = 0;
    pStorage->keyGenCapacity = keygenBytes;
    pStorage->encapsCapacity = encapsBytes;
    pStorage->decapsCapacity = decapsBytes;

    return sts;
}
