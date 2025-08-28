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

/*F*
//    Name: ippsMLKEM_GetSize
//
// Purpose: Queries the size of the IppsMLKEMState.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pSize == NULL
//    ippStsBadArgErr         schemeType is not supported
//    ippStsNoErr             no errors
//
// Parameters:
//    pSize      - output pointer with the context size
//    schemeType - input parameter specifying the scheme type
//
*F*/
IPPFUN(IppStatus, ippsMLKEM_GetSize, (int* pSize, IppsMLKEMParamSet schemeType))
{
    /* Test input parameters */
    IPP_BAD_PTR1_RET(pSize);

    Ipp8u kLoc = 0;
    switch (schemeType) {
    case IPPCP_ML_KEM_512:
        kLoc = 2;
        break;
    case IPPCP_ML_KEM_768:
        kLoc = 3;
        break;
    case IPPCP_ML_KEM_1024:
        kLoc = 4;
        break;
    default:
        return ippStsBadArgErr;
    }

    *pSize = (int)sizeof(IppsMLKEMState) +           /* base_ctx */
             kLoc * kLoc * (int)sizeof(Ipp16sPoly) + /* matrixAsize */
             CP_ML_KEM_ALIGNMENT;                    /* alignment */

    return ippStsNoErr;
}
