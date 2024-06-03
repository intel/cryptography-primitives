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

/*
//
//  Purpose:
//     Cryptography Primitive.
//        Initialization functions for internal methods and pointers inside AES-GCM context;
//        AES-GCM encryption kernels with the conditional noise injections mechanism;
//
*/

#if !defined(_PCP_AES_GCM_INTERNAL_FUNC_H)
#define _PCP_AES_GCM_INTERNAL_FUNC_H

#include "owndefs.h"
#include "pcpaes_internal_func.h"

#define cpAesGCM_setup_ptrs_and_methods OWNAPI(cpAesGCM_setup_ptrs_and_methods)
IPP_OWN_DECL(void, cpAesGCM_setup_ptrs_and_methods, (IppsAES_GCMState * pCtx, Ipp64u keyByteLen))

#define condNoisedGCMEncryption OWNAPI(condNoisedGCMEncryption)
IPP_OWN_DECL(void, condNoisedGCMEncryption, (const Ipp8u* pSrc, Ipp8u* pDst, int ptxt_len, IppsAES_GCMState* pState))

#define condNoisedGCMDecryption OWNAPI(condNoisedGCMDecryption)
IPP_OWN_DECL(void, condNoisedGCMDecryption, (const Ipp8u* pSrc, Ipp8u* pDst, int ptxt_len, IppsAES_GCMState* pState))

#endif /* _PCP_AES_GCM_INTERNAL_FUNC_H */
