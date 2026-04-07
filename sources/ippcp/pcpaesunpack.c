/*************************************************************************
* Copyright (C) 2013 Intel Corporation
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
//     Initialization of AES
// 
//  Contents:
//        ippsAESUnpack()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpaesm.h"
#include "pcprij128safe.h"
#include "pcptool.h"
#include "pcpaes_internal_func.h"

/*F*
//    Name: ippsAESUnpack
//
// Purpose: De-serialize buffer into the AES context.
//
// Returns:                Reason:
//    ippStsNullPtrErr        pBuffer== NULL
//                            pCtx == NULL
//    ippStsLengthErr         available size of buffer is not enough for operation
//    ippStsNoErr             no errors
//
// Parameters:
//    pBuffer     pointer to the fuffer
//    pCtx        pointer AES context
//    ctxSize     available size (in bytes) of AES context above
//
*F*/
IPPFUN(IppStatus, ippsAESUnpack, (const Ipp8u* pBuffer, IppsAESSpec* pCtx, int ctxSize))
{
    /* test pointers */
    IPP_BAD_PTR2_RET(pCtx, pBuffer);

    /* test available size of destination buffer */
    IPP_BADARG_RET(ctxSize < cpSizeofCtx_AES(), ippStsLengthErr);

    cpSize keysOffset  = (cpSize)(IPP_INT_PTR(RIJ_KEYS_BUFFER(pCtx)) - IPP_INT_PTR(pCtx));
    cpSize keysBufSize = sizeof(RIJ_KEYS_BUFFER(pCtx));

    /* restore all except expanded keys */
    CopyBlock(pBuffer, pCtx, keysOffset);

    /* restore pointers inside the state */
    cpAes_setup_ptrs_and_methods(pCtx);
    RIJ_ENC_SBOX(pCtx) = NULL;
    RIJ_DEC_SBOX(pCtx) = NULL;

    /* restore expanded keys (encryption and decryption) placed with correct alignment */
    CopyBlock(pBuffer + keysOffset, RIJ_EKEYS(pCtx), (keysBufSize - RIJ_ALIGNMENT));

    RIJ_SET_ID(pCtx);

#if (_AES_PROB_NOISE == _FEATURE_ON_)
    cpAESNoiseParams* pAESNoiseParams = &RIJ_NOISE_PARAMS(pCtx);
    CopyBlock(pBuffer + keysOffset + keysBufSize, pAESNoiseParams, cpSizeofNoise_Params());
#endif

    return ippStsNoErr;
}
