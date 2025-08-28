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

//-------------------------------//
//      Level 1 functions
//-------------------------------//

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"
#include "ml_kem_internal/ml_kem.h"

/*
 * Uses the encapsulation key and randomness to generate a key and an associated ciphertext.
 *
 *      K          - output pointer to the generated shared secret key K of size 32 bytes
 *      ciphertext - output pointer to the ciphertext of size 32*(d_{u}*k + d_{v})) bytes
 *      inpEncKey  - input pointer to the encapsulation key (public key) of size 384*k + 32 bytes
 *      m          - input parameter with generated randomness m of size 32 bytes
 *      mlkemCtx   - input pointer to ML KEM context
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_MLKEMencaps_internal, (Ipp8u K[CP_SHARED_SECRET_BYTES],
                                                  Ipp8u* ciphertext,
                                                  const Ipp8u* inpEncKey,
                                                  const Ipp8u m[CP_RAND_DATA_BYTES],
                                                  IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;

    /* (K,𝑟) <- G(m||H(ek)) */
    Ipp8u r_N[33];
    Ipp8u concatData[64];

    const Ipp32s ekByteSize     = 384 * mlkemCtx->params.k + 32;
    const Ipp32s ek_pkeByteSize = ekByteSize;

    /* H(ek) */
    sts = ippsHashMessage_rmf(inpEncKey, ek_pkeByteSize, r_N, ippsHashMethod_SHA3_256());
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    /* m||H(ek) */
    CopyBlock(m, concatData, CP_RAND_DATA_BYTES);
    CopyBlock(r_N, concatData + 32, 32);
    /* G(m||H(ek)) */
    sts = ippsHashMessage_rmf(concatData, 64, concatData, ippsHashMethod_SHA3_512());
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    CopyBlock(concatData, K, CP_SHARED_SECRET_BYTES);
    CopyBlock(concatData + CP_SHARED_SECRET_BYTES, r_N, 32);

    /* c <- K-PKE.Encrypt(ek, m, r) */
    sts = cp_KPKE_Encrypt(ciphertext, inpEncKey, m, r_N, mlkemCtx);

    /* Clear the copy of the secret */
    PurgeBlock(concatData, sizeof(concatData));

    return sts;
}
