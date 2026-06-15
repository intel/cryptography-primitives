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

#ifndef _IPPCP_ML_DSA_MEMORY_CONSUMPTION_H_
#define _IPPCP_ML_DSA_MEMORY_CONSUMPTION_H_

#include "hash/pcphash_rmf.h"

#include "ml_dsa.h"

/*
 * Memory consumption query function. The memory will be used to store temporary objects.
 * Input:  pMLDSACtx    - input pointer to ML-DSA context
 * Output: keygenBytes  - keyGen memory consumption, optional
 *         signBytes    - sign memory consumption, optional
 *         verifyBytes  - verify memory consumption, optional
 * Returns: ippStsNoErr on success, otherwise an error code.
 */
IPPCP_INLINE IppStatus mldsaMemoryConsumption(const IppsMLDSAState* pMLDSACtx,
                                              const int msg_size,
                                              int* keygenBytes,
                                              int* signBytes,
                                              int* verifyBytes)
{
    IppStatus sts        = ippStsErr;
    const Ipp8u k        = pMLDSACtx->params.k;
    const Ipp8u l        = pMLDSACtx->params.l;
    const Ipp8u lambda_4 = pMLDSACtx->params.lambda_div_4;
    const int ctx_size   = 256; // max context size for memory consumption estimation

    int locKeygenBytes = 0, locSignBytes = 0, locVerifyBytes = 0;
    int sizeof_polynom = sizeof(IppPoly);

    IppsHashMethod shake256_method;
    IppsHashMethod shake128_method;
    int hashCtxSizeShake_expandS = 0, hashCtxSizeShake_expandA = 0,
        hashCtxSizeShake_sampleInBall = 0;

    sts = ippsHashMethodSet_SHAKE256(&shake256_method, (256 * 8));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    sts = ippsHashGetSizeOptimal_rmf(&hashCtxSizeShake_expandS, &shake256_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    sts = ippsHashMethodSet_SHAKE128(&shake128_method, (3 * 32 * 8));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    sts = ippsHashGetSizeOptimal_rmf(&hashCtxSizeShake_expandA, &shake128_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    sts = ippsHashMethodSet_SHAKE256(&shake256_method, ((pMLDSACtx->params.tau + 8) * 8));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    sts = ippsHashGetSizeOptimal_rmf(&hashCtxSizeShake_sampleInBall, &shake256_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    /* KeyGen memory consumption */
    locKeygenBytes = (3 * k + l) * sizeof_polynom + 4 * CP_ML_ALIGNMENT;
    locKeygenBytes += IPP_MAX(hashCtxSizeShake_expandA, hashCtxSizeShake_expandS) + CP_ML_ALIGNMENT;

    if (msg_size != IPPCP_MLDSA_NO_MESSAGE) {
        /* Sign memory consumption */
        Ipp32s encodeSize =
            32 * k *
            cp_ml_bitlen((Ipp32u)((CP_ML_DSA_Q - 1) / (2 * pMLDSACtx->params.gamma_2) - 1));
        locSignBytes = (2 * k + l) * sizeof_polynom + 3 * CP_ML_ALIGNMENT;
#if !CP_ML_MEMORY_OPTIMIZATION
        locSignBytes += k * l * sizeof_polynom + CP_ML_ALIGNMENT;
#endif // !CP_ML_MEMORY_OPTIMIZATION
        int max_1 = (2 * k + l) * sizeof_polynom + 3 * CP_ML_ALIGNMENT +
                    IPP_MAX(l * sizeof_polynom + hashCtxSizeShake_expandA + 2 * CP_ML_ALIGNMENT,
                            IPP_MAX(k * sizeof_polynom + 64 + encodeSize + 2 * CP_ML_ALIGNMENT,
                                    hashCtxSizeShake_sampleInBall + CP_ML_ALIGNMENT)) +
                    k * sizeof_polynom + CP_ML_ALIGNMENT;
        locSignBytes += IPP_MAX(64 + (2 + ctx_size + msg_size) + CP_ML_ALIGNMENT, max_1);

        /* Verify memory consumption */
        int max_2 = 64 + IPP_MAX(2 + ctx_size + msg_size, encodeSize);
        max_2 = IPP_MAX(max_2, IPP_MAX(hashCtxSizeShake_expandA, hashCtxSizeShake_sampleInBall));

        locVerifyBytes = 3 * k * sizeof_polynom + lambda_4 + 4 * CP_ML_ALIGNMENT;
        locVerifyBytes += max_2 + CP_ML_ALIGNMENT;
    }

    if (keygenBytes)
        *keygenBytes = locKeygenBytes;
    if (signBytes)
        *signBytes = locSignBytes;
    if (verifyBytes)
        *verifyBytes = locVerifyBytes;

    return sts;
}

#endif /* _IPPCP_ML_DSA_MEMORY_CONSUMPTION_H_ */
