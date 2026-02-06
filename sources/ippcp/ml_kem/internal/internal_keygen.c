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
#include "stateless_pqc/ml_kem_internal/ml_kem.h"

/*
 * Uses randomness to generate an encapsulation key and a corresponding decapsulation key.
 *      outEncKey - output pointer to the output encapsulation key (public key)
 *      outDecKey - output pointer to the output decapsulation key (private key)
 *      d_k       - input parameter with generated randomness d appended by k
 *      z         - input parameter with generated randomness z
 *      mlkemCtx  - input pointer to ML KEM context
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_MLKEMkeyGen_internal, (Ipp8u * outEncKey,
                                                  Ipp8u* outDecKey,
                                                  const Ipp8u d_k[CP_RAND_DATA_BYTES+1],
                                                  const Ipp8u z[CP_RAND_DATA_BYTES],
                                                  IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;

    /* (ekPKE,dkPKE) <- K-PKE.KeyGen(d) */
    sts = cp_KPKE_KeyGen(outEncKey, outDecKey, d_k, mlkemCtx);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    const Ipp8u k               = mlkemCtx->params.k;
    const cpSize ekByteSize     = 384 * k + 32;
    const cpSize ek_pkeByteSize = ekByteSize;
    const cpSize dk_pkeByteSize = 384 * k;

    /* dk <- (dkPKE||ek||H(ek)||z) */
    CopyBlock(outEncKey, outDecKey + dk_pkeByteSize, ek_pkeByteSize);
    sts = ippsHashMessage_rmf(outEncKey,
                              ek_pkeByteSize,
                              outDecKey + dk_pkeByteSize + ek_pkeByteSize,
                              ippsHashMethod_SHA3_256());
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    CopyBlock(z, outDecKey + dk_pkeByteSize + ek_pkeByteSize + 32, CP_RAND_DATA_BYTES);

    return sts;
}
