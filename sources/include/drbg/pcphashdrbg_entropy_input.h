/*************************************************************************
* Copyright (C) 2026 Intel Corporation
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
//  Purpose:
//     Entropy input context
*/

#if !defined(_CP_HASHDRBG_ENTROPYINPUT_H)
#define _CP_HASHDRBG_ENTROPYINPUT_H

struct _cpEntropyInputCtx {
    Ipp32u idCtx;            /* Entropy input context identifier */
    Ipp8u* entropyInput;     /* Buffer to store both entropyInput and nonce for Instantiation
                                 and entropyInput for Reseeding */
    int entrInputBufBitsLen; /* The length of the Entropy input buffer set by a user */
    IppEntropyInputSupplier getEntropyInput; /* Callback function */
};

#define HASH_DRBG_ENTR_INPUT_SET_ID(ctx) \
    ((ctx)->idCtx = (Ipp32u)idCtxHashDRBGEntrInput ^ (Ipp32u)IPP_UINT_PTR(ctx))
#define HASH_DRBG_ENTR_INPUT_VALID_ID(ctx) \
    ((((ctx)->idCtx) ^ (Ipp32u)IPP_UINT_PTR((ctx))) == (Ipp32u)idCtxHashDRBGEntrInput)

#endif /* _CP_HASHDRBG_ENTROPYINPUT_H */
