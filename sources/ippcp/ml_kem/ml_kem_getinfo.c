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
//    Name: ippsMLKEM_GetInfo
//
// Purpose: Fills IppsMLKEMInfo structure with the sizes corresponding to the given scheme type.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pInfo == NULL
//    ippStsBadArgErr         schemeType is not supported
//    ippStsNoErr             no errors
//
// Parameters:
//    pInfo      - output pointer to the ML-KEM pInfo structure
//    schemeType - input parameter specifying the scheme type
//
*F*/
IPPFUN(IppStatus, ippsMLKEM_GetInfo, (IppsMLKEMInfo * pInfo, IppsMLKEMParamSet schemeType))
{
    /* Test input pointer */
    IPP_BAD_PTR1_RET(pInfo);

    switch (schemeType) {
    case IPPCP_ML_KEM_512: {
        pInfo->encapsKeySize    = 800;  /* 384*k + 32 */
        pInfo->decapsKeySize    = 1632; /* 786*k + 96 */
        pInfo->cipherTextSize   = 768;  /* 32*(d_{u}*k + d_{v})) */
        pInfo->sharedSecretSize = 32;   /* 32 bytes */
        break;
    }
    case IPPCP_ML_KEM_768: {
        pInfo->encapsKeySize    = 1184; /* 384*k + 32 */
        pInfo->decapsKeySize    = 2400; /* 786*k + 96 */
        pInfo->cipherTextSize   = 1088; /* 32*(d_{u}*k + d_{v})) */
        pInfo->sharedSecretSize = 32;   /* 32 bytes */
        break;
    }
    case IPPCP_ML_KEM_1024: {
        pInfo->encapsKeySize    = 1568; /* 384*k + 32 */
        pInfo->decapsKeySize    = 3168; /* 786*k + 96 */
        pInfo->cipherTextSize   = 1568; /* 32*(d_{u}*k + d_{v})) */
        pInfo->sharedSecretSize = 32;   /* 32 bytes */
        break;
    }
    default:
        return ippStsBadArgErr;
    }
    return ippStsNoErr;
}
