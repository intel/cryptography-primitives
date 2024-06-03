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

/*
//
//  Purpose:
//     Cryptography Primitive.
//     AES-GCM functionality
//
//  Contents:
//        ippsAES_GCMReinit()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpaesm.h"
#include "pcpaes_gcm_internal_func.h"
#include "pcptool.h"

#if (_IPP32E >= _IPP32E_K0)
#include "pcpaesauthgcm_avx512.h"
#else
#include "pcpaesauthgcm.h"
#endif /* #if(_IPP32E>=_IPP32E_K0) */

/*F*
//    Name: ippsAES_GCMReinit
//
// Purpose: Re-init AES_GCM context for future usage -
// the state of the context left unchanged, just the internal stuff is updated
// (it's useful when the context physically lies in the same memory, but its
//  virtual address changes - some pointers inside become stale and need to be re-initialized).
// Important note: this API shouldn't be used to re-initialize a context that was copied
// from some original context, computations in this case may be incorrect.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pState == NULL
//    ippStsNoErr             no errors
//
// Parameters:
//    pState      pointer to the AES-GCM context to be re-initialized
//
*F*/
IPPFUN(IppStatus, ippsAES_GCMReinit, (IppsAES_GCMState * pState))
{
   /* test pState pointer */
   IPP_BAD_PTR1_RET(pState);

   /* use aligned context */
   pState = (IppsAES_GCMState *)(IPP_ALIGNED_PTR(pState, AESGCM_ALIGNMENT));

   /* set proper GCM context id */
   AESGCM_SET_ID(pState);

   Ipp64u keyByteLen;
/* re-init pointers inside the cipher context */
#if (_IPP32E >= _IPP32E_K0)
   keyByteLen = AES_GCM_KEY_LEN(pState);
#else
   IppsAESSpec *pAesCtx = AESGCM_CIPHER(pState);
   /* set proper cipher context id*/
   RIJ_SET_ID(pAesCtx);
   keyByteLen = (Ipp64u)RIJ_NK(pAesCtx) * RIJ_BYTES_IN_WORD;

   cpAes_setup_ptrs_and_methods(pAesCtx);
#endif

   /* re-init pointers inside the AES-GCM context */
   cpAesGCM_setup_ptrs_and_methods(pState, keyByteLen);

   return ippStsNoErr;
}
