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

#ifndef _IPPCP_ML_KEM_MEMORY_CONSUMPTION_H_
#define _IPPCP_ML_KEM_MEMORY_CONSUMPTION_H_

#include "ml_kem_internal/ml_kem.h"

/*
 * Memory consumption query function. The memory will be used to store temporary objects. 
 * Input:  pMLKEMCtx    - input pointer to ML-KEM context
 * Output: keygenBytes  - keyGen memory consumption, optional
 *         encapsBytes  - encaps memory consumption, optional
 *         decapsBytes  - decaps memory consumption, optional
 * Returns: ippStsNoErr on success, otherwise an error code.
 */
__IPPCP_INLINE IppStatus mlkemMemoryConsumption(const IppsMLKEMState* pMLKEMCtx,
                                                int* keygenBytes,
                                                int* encapsBytes,
                                                int* decapsBytes)
{
    IppStatus sts    = ippStsNoErr;
    const Ipp8u k    = pMLKEMCtx->params.k;
    const Ipp16u d_u = pMLKEMCtx->params.d_u;
    const Ipp8u d_v  = pMLKEMCtx->params.d_v;
    const Ipp8u eta1 = pMLKEMCtx->params.eta1;

    int locKeygenBytes = 0, locEncapsBytes = 0, locDecapsBytes = 0;

    int hashCtxSizeShake = 0;
    sts = ippsHashGetSizeOptimal_rmf(&hashCtxSizeShake, ippsHashMethod_SHAKE256(3 * 256 * 8));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    /* keyGen memory consumption */
    locKeygenBytes = eta1 * 64 + 3 * k * (int)sizeof(Ipp16sPoly) + (int)sizeof(Ipp16sPoly) +
                     hashCtxSizeShake + 5 * CP_ML_KEM_ALIGNMENT;

    /* Encaps memory consumption */
    locEncapsBytes = 4 * (k * (int)sizeof(Ipp16sPoly)) + eta1 * 64 + 4 * (int)sizeof(Ipp16sPoly) +
                     hashCtxSizeShake + 9 * CP_ML_KEM_ALIGNMENT;

    /* Decaps memory consumption */
    sts = ippsHashGetSizeOptimal_rmf(&hashCtxSizeShake, ippsHashMethod_SHAKE256(32 * 8));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    int hashCtxSizeSHA3_512 = 0;
    sts = ippsHashGetSizeOptimal_rmf(&hashCtxSizeSHA3_512, ippsHashMethod_SHA3_512());
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    locDecapsBytes = IPP_MAX(hashCtxSizeShake, hashCtxSizeSHA3_512) + 3 * (int)sizeof(Ipp16sPoly) +
                     2 * (k * (int)sizeof(Ipp16sPoly)) + 32 * (d_u * k + d_v) + locEncapsBytes +
                     3 * CP_ML_KEM_ALIGNMENT;

    if (keygenBytes)
        *keygenBytes = locKeygenBytes;
    if (encapsBytes)
        *encapsBytes = locEncapsBytes;
    if (decapsBytes)
        *decapsBytes = locDecapsBytes;

    return sts;
}

#endif /* _IPPCP_ML_KEM_MEMORY_CONSUMPTION_H_ */
