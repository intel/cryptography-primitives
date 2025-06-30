/*************************************************************************
* Copyright (C) 2022 Intel Corporation
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

/* 
// 
//  Purpose:
//     Cryptography Primitive.
//     AES-CMAC noise setup function
// 
//  Contents:
//     ippsAES_CMACSetupNoise
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpcmac.h"
#include "pcptool.h"

/*F*
//    Name: ippsAES_CMACSetupNoise
//
// Purpose: AES-CMAC Setup Noise
//
// Returns:                Reason:
//    ippStsNullPtrErr           pState == NULL
//    ippStsContextMatchErr      AES context is invalid
//    ippStsLengthErr            noiseLevel > 4
//    ippStsNotSupportedModeErr  Mistletoe3 mitigation isn't applicable for current CPU
//                               (no support of Intel® Advanced Encryption Standard New Instructions (Intel® AES-NI) or 
//                               vector extensions of Intel® AES-NI)
//    ippStsNoErr                no errors
//
// Parameters:
//    noiseLevel     the value of this parameter is directly 
//                   proportional to the amount of noise injected
//                   Increasing noise level by 1 means the delay
//                   (performance impact) is doubled
//    pState         pointer to the AES context
//
*F*/
IPPFUN(IppStatus, ippsAES_CMACSetupNoise, (Ipp32u noiseLevel, IppsAES_CMACState* pState))
{
#if (_AES_PROB_NOISE == _FEATURE_ON_)
    /* test context */
    IPP_BAD_PTR1_RET(pState);
    /* test ID */
    IPP_BADARG_RET(!VALID_AESCMAC_ID(pState), ippStsContextMatchErr);

    /* test noise level range */
    IPP_BADARG_RET(noiseLevel > 4, ippStsLengthErr);

    cpAESNoiseParams* params = (cpAESNoiseParams*)&AESCMAC_NOISE_PARAMS(pState);

    /* set up the parameters with initial values */
    AES_NOISE_RAND(params)  = 0;
    AES_NOISE_LEVEL(params) = noiseLevel;

    return ippStsNoErr;
#else
    /* To remove MSVC warning C4100: 'XXX': unreferenced formal parameter*/
    IPP_UNREFERENCED_PARAMETER(noiseLevel);
    IPP_UNREFERENCED_PARAMETER(pState);
    return ippStsNotSupportedModeErr;
#endif
}
