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
//    Name: ippsMLKEM_KeyGenBufferGetSize
//
// Purpose: Queries the size of the ippsMLKEM_KeyGen working buffer.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize     == NULL
//                            pMLKEMCtx == NULL
//    ippStsContextMatchErr   pMLKEMCtx is not initialized
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize     - output pointer with the working buffer size
//    pMLKEMCtx - input pointer to ML KEM context
//
*F*/
IPPFUN(IppStatus, ippsMLKEM_KeyGenBufferGetSize, (int* pSize, const IppsMLKEMState* pMLKEMCtx))
{
    /* Test input parameters */
    IPP_BAD_PTR2_RET(pSize, pMLKEMCtx);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_KEM_VALID_ID(pMLKEMCtx), ippStsContextMatchErr);

    // Total storage memory consumption
    int keyGenStorageSize = 0;
    IppStatus sts         = mlkemMemoryConsumption(pMLKEMCtx, &keyGenStorageSize, NULL, NULL);

    *pSize = keyGenStorageSize;

    return sts;
}

/*F*
//    Name: ippsMLKEM_EncapsBufferGetSize
//
// Purpose: Queries the size of the ippsMLKEM_Encaps working buffer.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize     == NULL
//                            pMLKEMCtx == NULL
//    ippStsContextMatchErr   pMLKEMCtx is not initialized
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize     - output pointer with the working buffer size
//    pMLKEMCtx - input pointer to ML KEM context
//
*F*/
IPPFUN(IppStatus, ippsMLKEM_EncapsBufferGetSize, (int* pSize, const IppsMLKEMState* pMLKEMCtx))
{
    /* Test input parameters */
    IPP_BAD_PTR2_RET(pSize, pMLKEMCtx);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_KEM_VALID_ID(pMLKEMCtx), ippStsContextMatchErr);

    // Total storage memory consumption
    int encapsStorageSize = 0;
    IppStatus sts         = mlkemMemoryConsumption(pMLKEMCtx, NULL, &encapsStorageSize, NULL);

    *pSize = encapsStorageSize;

    return sts;
}

/*F*
//    Name: ippsMLKEM_DecapsBufferGetSize
//
// Purpose: Queries the size of the ippsMLKEM_Decaps working buffer.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize     == NULL
//                            pMLKEMCtx == NULL
//    ippStsContextMatchErr   pMLKEMCtx is not initialized
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize     - output pointer with the working buffer size
//    pMLKEMCtx - input pointer to ML KEM context
//
*F*/
IPPFUN(IppStatus, ippsMLKEM_DecapsBufferGetSize, (int* pSize, const IppsMLKEMState* pMLKEMCtx))
{
    /* Test input parameters */
    IPP_BAD_PTR2_RET(pSize, pMLKEMCtx);
    /* Test the provided state */
    IPP_BADARG_RET(!CP_ML_KEM_VALID_ID(pMLKEMCtx), ippStsContextMatchErr);

    // Total storage memory consumption
    int decapsStorageSize = 0;
    IppStatus sts         = mlkemMemoryConsumption(pMLKEMCtx, NULL, NULL, &decapsStorageSize);

    *pSize = decapsStorageSize;

    return sts;
}
