/*******************************************************************************
* Copyright 2016 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

/*
//
//  Purpose:
//     Cryptography Primitive. AES keys expansion
//
//  Contents:
//        aes_DecKeyExpansion_NI()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpaesm.h"
#include "pcpaes_keys_ni.h"

#if (_AES_NI_ENABLING_==_FEATURE_ON_) || (_AES_NI_ENABLING_==_FEATURE_TICKTOCK_)

//////////////////////////////////////////////////////////////////////
/*
// AES decryption key schelule
*/
IPP_OWN_DEFN (void, aes_DecKeyExpansion_NI, (Ipp8u* decKeys, const Ipp8u* encKeys, int nr))
{
   __m128i* encKeys16 = (__m128i*)encKeys;
   __m128i* decKeys16 = (__m128i*)decKeys;

   decKeys16[nr] = encKeys16[nr];
   for(nr-=1; nr > 0; nr--) {
      decKeys16[nr] = _mm_aesimc_si128(encKeys16[nr]);
   }
   decKeys16[0] = encKeys16[0];
}

#endif /* #if (_AES_NI_ENABLING_==_FEATURE_ON_) || (_AES_NI_ENABLING_==_FEATURE_TICKTOCK_) */

