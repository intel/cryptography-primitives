/*************************************************************************
* Copyright (C) 2015 Intel Corporation
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
//     PRNG Functions
//
//  Contents:
//        ippsPRNGenRDRAND()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpbn.h"
#include "pcptool.h"
#include "pcpprng_genhw.h"

/*F*
// Name: ippsPRNGenRDRAND
//
// Purpose: Generates a pseudorandom unsigned 32-bit int buffer of the
// specified nBits length using the RDRAND instruction. If the last 32-bit
// int is not filled, its most significant bits are zeroed.
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pRand
//
//    ippStsLengthErr            1 > nBits
//
//    ippStsNotSupportedModeErr  unsupported rdrand instruction
//
//    ippStsErr                  random bit sequence can't be generated
//
//    ippStsNoErr                no error
//
// Parameters:
//    pRand    pointer to the buffer
//    nBits    number of bits be requested
//    pCtx     pointer to the context, unused, can be NULL
*F*/
IPPFUN(IppStatus, ippsPRNGenRDRAND,(Ipp32u* pRand, int nBits, void* pCtx))
{
   /* test PRNG buffer */
   IPP_BAD_PTR1_RET(pRand);

   /* test sizes */
   IPP_BADARG_RET(nBits< 1, ippStsLengthErr);

   IPP_UNREFERENCED_PARAMETER(pCtx);

   #if ((_IPP>=_IPP_G9) || (_IPP32E>=_IPP32E_E9))
   if( IsFeatureEnabled(ippCPUID_RDRAND) ) {
      cpSize rndSize = BITS2WORD32_SIZE(nBits);
      Ipp32u rndMask = MAKEMASK32(nBits);

      if(cpRandHW_buffer(pRand, rndSize)) {
         pRand[rndSize-1] &= rndMask;
         return ippStsNoErr;
      }
      else
         return ippStsErr;
   }
   /* unsupported rdrand instruction */
   else
   #endif
      IPP_ERROR_RET(ippStsNotSupportedModeErr);
}
