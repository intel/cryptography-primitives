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

#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"

#include "stateless_pqc/ml_dsa/ml_dsa.h"

// =============================================
// 7.3 Pseudorandom Sampling
// =============================================

// Algorithm 29 SampleInBall(rho)
IPP_OWN_DEFN(IppStatus,
             cp_ml_sampleInBall,
             (const Ipp8u* rho, IppPoly* c, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts             = ippStsErr;
    _cpMLDSAStorage* pStorage = &mldsaCtx->storage;
    Ipp8u lambda_4            = mldsaCtx->params.lambda_div_4;
    IppsHashMethod hash_method;

    for (Ipp32u i = 0; i < CP_ML_N; ++i) {
        c->values[i] = 0;
    }

    sts = ippsHashMethodSet_SHAKE256(&hash_method, ((mldsaCtx->params.tau + 8) * 8));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    int hash_size = 0;
    sts           = ippsHashGetSizeOptimal_rmf(&hash_size, &hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    IppsHashState_rmf* hash_state =
        (IppsHashState_rmf*)cp_mlStorageAllocate(pStorage, hash_size + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((hash_state == NULL), ippStsMemAllocErr);

    sts = ippsHashInit_rmf(hash_state, &hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    sts = ippsHashUpdate_rmf(rho, lambda_4, hash_state);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    Ipp8u s[8];
    sts = ippsHashSqueeze_rmf(s, 8, hash_state);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    for (Ipp8u i = 0; i < mldsaCtx->params.tau; ++i) {
        Ipp8u j;
        Ipp8u shifted_i = i + (Ipp8u)(CP_ML_N - mldsaCtx->params.tau);
        sts             = ippsHashSqueeze_rmf(&j, 1, hash_state);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);

        Ipp16u iter = 0;
        while (j > shifted_i && iter < CP_ML_DSA_MAX_SAMPLE_IN_BALL_ITERATIONS) {
            sts = ippsHashSqueeze_rmf(&j, 1, hash_state);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
            iter++;
        }
        // zeroize data and release the memory if max iterations reached
        if (iter == CP_ML_DSA_MAX_SAMPLE_IN_BALL_ITERATIONS) {
            PurgeBlock(s, sizeof(s));       // zeroize secrets
            PurgeBlock(c->values, CP_ML_N); // zeroize secrets
            sts = cp_mlStorageRelease(pStorage, hash_size + CP_ML_ALIGNMENT);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);

            return ippStsMLDSAMaxIterations;
        }
        c->values[shifted_i] = c->values[j];

        // extract bits from s
        Ipp8u byte_index = i >> 3;
        Ipp8u bit_offset = i & 7;
        Ipp8u bit        = (s[byte_index] >> bit_offset) & 1;

        c->values[j] = (bit == 1) ? -1 : 1;
    }
    PurgeBlock(s, sizeof(s)); // zeroize secrets

    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage, hash_size + CP_ML_ALIGNMENT);
    return sts;
}

// Algorithm 30 RejNTTPoly(rho)
#if (_IPP32E >= _IPP32E_K0)

#define CP_ML_DSA_SAMPLENTT_BUFF_SIZE (258)

IPP_OWN_DEFN(IppStatus,
             cp_ml_rejNTTPoly_MB4,
             (Ipp8u * rho1, Ipp8u* rho2, Ipp8u* rho3, Ipp8u* rho4, Ipp32s numBuffers, IppPoly* a))
{
    /* Prepare the multi-buffer hash state */
    Ipp8u state_buffer_mb4[STATE_x4_SIZE];
    cpSHA3_SHAKE128Ctx_mb4 state_mb4;
    state_mb4.ctx = state_buffer_mb4;

    /* Update hash state */
    cp_SHA3_SHAKE128_InitMB4(&state_mb4);
    cp_SHA3_SHAKE128_AbsorbMB4(&state_mb4, rho1, rho2, rho3, rho4, 34);
    cp_SHA3_SHAKE128_FinalizeMB4(&state_mb4);

    /* The hash squeeze loop for up to 4 buffers */
    Ipp32u buffer_bytes_used = 0;
    Ipp8u s[4][CP_ML_DSA_SAMPLENTT_BUFF_SIZE];
    /* Squeeze the first big block unconditionally */
    cp_SHA3_SHAKE128_SqueezeMB4(s[0], s[1], s[2], s[3], CP_ML_DSA_SAMPLENTT_BUFF_SIZE, &state_mb4);
    /* Looping index is separate for each buffer */
    Ipp16u j[4] = { 0, 0, 0, 0 };
    Ipp32s result;
    Ipp16u iter = 0;
    while (
        ((((numBuffers - 1) >= 0) && (j[0] < 256)) || (((numBuffers - 2) >= 0) && (j[1] < 256)) ||
         (((numBuffers - 3) >= 0) && (j[2] < 256)) || (((numBuffers - 4) >= 0) && (j[3] < 256))) &&
        iter < CP_ML_DSA_MAX_REJ_NTT_POLY_ITERATIONS) {
        if (buffer_bytes_used >= CP_ML_DSA_SAMPLENTT_BUFF_SIZE) {
            cp_SHA3_SHAKE128_SqueezeMB4(s[0],
                                        s[1],
                                        s[2],
                                        s[3],
                                        CP_ML_DSA_SAMPLENTT_BUFF_SIZE,
                                        &state_mb4);
            buffer_bytes_used = 0;
        }

        // Fill elements of up to 4 polynomials
        for (Ipp32s buf = 0; buf < numBuffers; buf++) {
            // a->values[j] = cp_ml_coeffFromThreeBytes(s[3 * idx], s[3 * idx + 1], s[3 * idx + 2]);
            result = cp_ml_coeffFromThreeBytes(s[buf][buffer_bytes_used + 0],
                                               s[buf][buffer_bytes_used + 1],
                                               s[buf][buffer_bytes_used + 2]);
            if ((result != -1) && (j[buf] < 256)) {
                a[buf].values[j[buf]] = result;
                j[buf]++;
            }
        }
        buffer_bytes_used += 3;
        iter++;
    }
    /* Release locally used storage */
    PurgeBlock(j, sizeof(j));
    PurgeBlock(state_buffer_mb4, sizeof(state_buffer_mb4));
    for (Ipp32s i = 0; i < 4; i++) {
        PurgeBlock(s[i], CP_ML_DSA_SAMPLENTT_BUFF_SIZE);
    }

    if (iter >= CP_ML_DSA_MAX_REJ_NTT_POLY_ITERATIONS) {
        PurgeBlock(a->values, CP_ML_N); // zeroize secrets
        return ippStsMLDSAMaxIterations;
    }
    return ippStsNoErr;
}

#else

IPP_OWN_DEFN(IppStatus, cp_ml_rejNTTPoly, (Ipp8u * rho, IppPoly* a, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts             = ippStsErr;
    _cpMLDSAStorage* pStorage = &mldsaCtx->storage;
    Ipp16u j                  = 0;
    Ipp8u s[CP_ML_DSA_N_BLOCKS * 3];
    IppsHashMethod hash_method;

    sts = ippsHashMethodSet_SHAKE128(&hash_method, CP_ML_DSA_N_BLOCKS * 3 * 8);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    int hash_size = 0;
    sts           = ippsHashGetSizeOptimal_rmf(&hash_size, &hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    IppsHashState_rmf* hash_state =
        (IppsHashState_rmf*)cp_mlStorageAllocate(pStorage, hash_size + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((hash_state == NULL), ippStsMemAllocErr);

    sts = ippsHashInit_rmf(hash_state, &hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    sts = ippsHashUpdate_rmf(rho, 34, hash_state);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    Ipp16u iter = 0;
    while (j < (Ipp16u)CP_ML_N && iter < CP_ML_DSA_MAX_REJ_NTT_POLY_ITERATIONS) {
        sts = ippsHashSqueeze_rmf(s, CP_ML_DSA_N_BLOCKS * 3, hash_state);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);

        for (int idx = 0; idx < CP_ML_DSA_N_BLOCKS && j < (Ipp16u)CP_ML_N; ++idx) {
            a->values[j] = cp_ml_coeffFromThreeBytes(s[3 * idx], s[3 * idx + 1], s[3 * idx + 2]);
            if (a->values[j] != -1) {
                j++;
            }
        }
        iter++;
    }
    PurgeBlock(s, sizeof(s)); // zeroize secrets

    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage, hash_size + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    if (iter >= CP_ML_DSA_MAX_REJ_NTT_POLY_ITERATIONS) {
        PurgeBlock(a->values, CP_ML_N); // zeroize secrets
        return ippStsMLDSAMaxIterations;
    }
    return sts;
}
#endif /* #if (_IPP32E >= _IPP32E_K0) */

// Algorithm 31 RejBoundedPoly(rho)

#if (_IPP32E >= _IPP32E_K0)

#define CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE (256)

IPP_OWN_DEFN(IppStatus,
             cp_ml_rejBoundedPoly_MB4,
             (Ipp8u * rho1,
              Ipp8u* rho2,
              Ipp8u* rho3,
              Ipp8u* rho4,
              Ipp32s numBuffers,
              IppPoly* s,
              IppsMLDSAState* mldsaCtx))
{
    /* Prepare the multi-buffer hash state */
    Ipp8u state_buffer_mb4[STATE_x4_SIZE];
    cpSHA3_SHAKE256Ctx_mb4 state_mb4;
    state_mb4.ctx = state_buffer_mb4;

    /* Update hash state */
    cp_SHA3_SHAKE256_InitMB4(&state_mb4);
    cp_SHA3_SHAKE256_AbsorbMB4(&state_mb4, rho1, rho2, rho3, rho4, 66);
    cp_SHA3_SHAKE256_FinalizeMB4(&state_mb4);

    /* The hash squeeze loop for up to 4 buffers */
    Ipp32u buffer_bytes_used = 0;
    Ipp8u z[4][CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE];
    /* Squeeze the first big block unconditionally */
    cp_SHA3_SHAKE256_SqueezeMB4(z[0],
                                z[1],
                                z[2],
                                z[3],
                                CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE,
                                &state_mb4);
    /* Looping index is separate for each buffer */
    Ipp16u j[4] = { 0, 0, 0, 0 };
    Ipp8s z0, z1;
    Ipp16u iter = 0;
    while (
        ((((numBuffers - 1) >= 0) && (j[0] < 256)) || (((numBuffers - 2) >= 0) && (j[1] < 256)) ||
         (((numBuffers - 3) >= 0) && (j[2] < 256)) || (((numBuffers - 4) >= 0) && (j[3] < 256))) &&
        iter < CP_ML_DSA_MAX_REJ_BOUNDED_POLY_ITERATIONS) {
        if (buffer_bytes_used >= CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE) {
            cp_SHA3_SHAKE256_SqueezeMB4(z[0],
                                        z[1],
                                        z[2],
                                        z[3],
                                        CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE,
                                        &state_mb4);
            buffer_bytes_used = 0;
        }

        // Fill elements of up to 4 polynomials
        for (Ipp32s buf = 0; buf < numBuffers; buf++) {
            z0 = cp_ml_coeffFromHalfByte(z[buf][buffer_bytes_used] & 15, mldsaCtx->params.eta);
            z1 = cp_ml_coeffFromHalfByte(z[buf][buffer_bytes_used] >> 4, mldsaCtx->params.eta);
            if (z0 != -100 && j[buf] < (Ipp16u)CP_ML_N) {
                s[buf].values[j[buf]] = z0;
                j[buf]++;
            }
            if (z1 != -100 && j[buf] < (Ipp16u)CP_ML_N) {
                s[buf].values[j[buf]] = z1;
                j[buf]++;
            }
        }
        buffer_bytes_used++;
        iter++;
    }
    /* Release locally used storage */
    PurgeBlock(j, sizeof(j));
    PurgeBlock(state_buffer_mb4, sizeof(state_buffer_mb4));
    for (Ipp32s i = 0; i < 4; i++) {
        PurgeBlock(z[i], CP_ML_DSA_SAMPLENTT_BUFF_SIZE);
    }

    if (iter >= CP_ML_DSA_MAX_REJ_BOUNDED_POLY_ITERATIONS) {
        PurgeBlock(s->values, CP_ML_N); // zeroize secrets
        return ippStsMLDSAMaxIterations;
    }
    return ippStsNoErr;
}

#else

IPP_OWN_DEFN(IppStatus, cp_ml_rejBoundedPoly, (Ipp8u * rho, IppPoly* a, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts             = ippStsErr;
    _cpMLDSAStorage* pStorage = &mldsaCtx->storage;

    IppsHashMethod hash_method;
    sts = ippsHashMethodSet_SHAKE256(&hash_method, (CP_ML_N * 8));
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    int hash_size = 0;
    sts           = ippsHashGetSizeOptimal_rmf(&hash_size, &hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    IppsHashState_rmf* hash_state =
        (IppsHashState_rmf*)cp_mlStorageAllocate(pStorage, hash_size + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((hash_state == NULL), ippStsMemAllocErr);

    sts = ippsHashInit_rmf(hash_state, &hash_method);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    sts = ippsHashUpdate_rmf(rho, 66, hash_state);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    Ipp32u j = 0;
    Ipp8u z[CP_ML_DSA_N_BLOCKS];
    Ipp8s z0, z1;
    Ipp16u iter = 0;
    while (j < CP_ML_N && iter < CP_ML_DSA_MAX_REJ_BOUNDED_POLY_ITERATIONS) {
        sts = ippsHashSqueeze_rmf(z, CP_ML_DSA_N_BLOCKS, hash_state);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);

        for (int i = 0; i < CP_ML_DSA_N_BLOCKS && j < (Ipp16u)CP_ML_N; i++) {
            z0 = cp_ml_coeffFromHalfByte(z[i] & 15, mldsaCtx->params.eta);
            z1 = cp_ml_coeffFromHalfByte(z[i] >> 4, mldsaCtx->params.eta);
            if (z0 != -100) {
                a->values[j] = z0;
                j++;
            }
            if (z1 != -100 && j < (Ipp16u)CP_ML_N) {
                a->values[j] = z1;
                j++;
            }
        }
        iter++;
    }
    PurgeBlock(z, sizeof(z)); // zeroize secrets

    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage, hash_size + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    if (iter >= CP_ML_DSA_MAX_REJ_BOUNDED_POLY_ITERATIONS) {
        PurgeBlock(a->values, CP_ML_N); // zeroize secrets
        return ippStsMLDSAMaxIterations;
    }

    return sts;
}
#endif /* #if (_IPP32E >= _IPP32E_K0) */

// Algorithm 32 ExpandA(rho)
IPP_OWN_DEFN(IppStatus,
             cp_ml_expandA,
             (const Ipp8u* rho, IppPoly* matrixA, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts = ippStsErr;
    const Ipp8u k = mldsaCtx->params.k;
    const Ipp8u l = mldsaCtx->params.l;

    /* Multi-buffer approach */
#if (_IPP32E >= _IPP32E_K0)
    /* Prepare rho for the multi-buffer processing */
    Ipp8u rho_j_i[4][34];
    CopyBlock(rho, rho_j_i[0], 32);
    CopyBlock(rho, rho_j_i[1], 32);
    CopyBlock(rho, rho_j_i[2], 32);
    CopyBlock(rho, rho_j_i[3], 32);

    Ipp8u nBuffs    = 4;
    Ipp8u remainder = (Ipp8u)(k * l & (nBuffs - 1));
    Ipp8u i         = 0;
    for (; i < k * l - remainder; i += nBuffs) {
        for (Ipp8u j = 0; j < nBuffs; j++) {
            Ipp8u ij = i + j;
            Ipp8u r  = ij / l;
            Ipp8u s  = ij - (r * l);

            rho_j_i[j][32] = s;
            rho_j_i[j][33] = r;
        }

        sts = cp_ml_rejNTTPoly_MB4(rho_j_i[0],
                                   rho_j_i[1],
                                   rho_j_i[2],
                                   rho_j_i[3],
                                   nBuffs,
                                   matrixA + i);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }

    // process remainder
    if (remainder != 0) {
        nBuffs = remainder;
        for (Ipp8u j = 0; j < nBuffs; j++) {
            Ipp8u ij = i + j;
            Ipp8u r  = ij / l;
            Ipp8u s  = ij - (r * l);

            rho_j_i[j][32] = s;
            rho_j_i[j][33] = r;
        }

        sts = cp_ml_rejNTTPoly_MB4(rho_j_i[0],
                                   rho_j_i[1],
                                   rho_j_i[2],
                                   rho_j_i[3],
                                   nBuffs,
                                   &matrixA[i]);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
    /* Release locally used storage */
    for (i = 0; i < 4; i++) {
        PurgeBlock(rho_j_i[i], 34);
    }

#else
    Ipp8u rho_[34];
    CopyBlock(rho, rho_, 32);

    for (Ipp8u r = 0; r < k; r++) {
        for (Ipp8u s = 0; s < l; s++) {
            rho_[32] = s;
            rho_[33] = r;
            sts      = cp_ml_rejNTTPoly(rho_, matrixA + (r * l + s), mldsaCtx);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);
        }
    }
    PurgeBlock(rho_, sizeof(rho_)); // zeroize secrets
#endif /* #if (_IPP32E >= _IPP32E_K0) */
    return sts;
}

// Algorithm 33 ExpandS(rho)
IPP_OWN_DEFN(IppStatus,
             cp_ml_expandS,
             (Ipp8u * rho, IppPoly* s1, IppPoly* s2, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts = ippStsErr;

    const Ipp8u k = mldsaCtx->params.k;
    const Ipp8u l = mldsaCtx->params.l;

    /* Multi-buffer approach */
#if (_IPP32E >= _IPP32E_K0)
    /* Prepare rho for the multi-buffer processing */
    Ipp8u rho_j_i[4][66];
    CopyBlock(rho, rho_j_i[0], 64);
    CopyBlock(rho, rho_j_i[1], 64);
    CopyBlock(rho, rho_j_i[2], 64);
    CopyBlock(rho, rho_j_i[3], 64);

    Ipp8u nIters = (l + 3) / 4;
    Ipp8u nBuffs = 4;

    // process 1st loop over l
    for (Ipp8u iter = 0; iter < nIters; iter++) {
        for (Ipp8u i = 0; i < nBuffs; i++) {
            rho_j_i[i][64] = i + iter * 4;
            rho_j_i[i][65] = 0;
        }

        sts = cp_ml_rejBoundedPoly_MB4(rho_j_i[0],
                                       rho_j_i[1],
                                       rho_j_i[2],
                                       rho_j_i[3],
                                       nBuffs,
                                       s1 + iter * 4,
                                       mldsaCtx);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);

        nBuffs = l - nBuffs;
    }

    // process 2nd loop over k
    nIters = (k + 3) / 4;
    nBuffs = 4;
    for (Ipp8u iter = 0; iter < nIters; iter++) {
        for (Ipp8u i = 0; i < nBuffs; i++) {
            rho_j_i[i][64] = i + iter * 4 + l;
            rho_j_i[i][65] = 0;
        }

        sts = cp_ml_rejBoundedPoly_MB4(rho_j_i[0],
                                       rho_j_i[1],
                                       rho_j_i[2],
                                       rho_j_i[3],
                                       nBuffs,
                                       s2 + iter * 4,
                                       mldsaCtx);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        nBuffs = k - nBuffs;
    }
    /* Release locally used storage */
    for (Ipp32s i = 0; i < 4; i++) {
        PurgeBlock(rho_j_i[i], 66);
    }

#else

    Ipp8u rho_[66];
    CopyBlock(rho, rho_, 64);
    for (Ipp8u r = 0; r < l; r++) {
        rho_[64] = r;
        rho_[65] = 0;
        sts      = cp_ml_rejBoundedPoly(rho_, s1 + r, mldsaCtx);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }

    for (Ipp8u r = 0; r < k; r++) {
        rho_[64] = r + l;
        rho_[65] = 0;
        sts      = cp_ml_rejBoundedPoly(rho_, s2 + r, mldsaCtx);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
    }
    PurgeBlock(rho_, sizeof(rho_)); // zeroize secrets
#endif /* #if (_IPP32E >= _IPP32E_K0) */
    return sts;
}

// Algorithm 34 ExpandMask(rho, mu)
IPP_OWN_DEFN(IppStatus,
             cp_ml_expandMask,
             (Ipp8u * rho, Ipp32u mu, IppPoly* out, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts             = ippStsErr;
    Ipp32s gamma_1            = mldsaCtx->params.gamma_1;
    Ipp8u c                   = 1 + cp_ml_bitlen((Ipp32u)(gamma_1 - 1));
    _cpMLDSAStorage* pStorage = &mldsaCtx->storage;

    IppsHashMethod shake256_method;
    Ipp8u* v = cp_mlStorageAllocate(pStorage, 32 * c + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((v == NULL), ippStsMemAllocErr);

    Ipp8u rho_[66];
    CopyBlock(rho, rho_, 64);

    for (Ipp8u r = 0; r < mldsaCtx->params.l; r++) {
        rho_[64] = (mu + r) & 0xFF;
        rho_[65] = ((mu + r) >> 8) & 0xFF;
        sts      = ippsHashMethodSet_SHAKE256(&shake256_method, (8 * 32 * c));
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        sts = ippsHashMessage_rmf(rho_, 66, v, &shake256_method);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        cp_ml_bitUnpack(v, (Ipp32s)gamma_1, cp_ml_bitlen((Ipp32u)(2 * gamma_1 - 1)), out + r);
    }
    PurgeBlock(rho_, sizeof(rho_)); // zeroize secrets
    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage, 32 * c + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    return sts;
}

// =============================================
// 7.6 Arithmetic Under NTT
// =============================================

// Algorithm 32.1 ExpandA(rho) combined with Algorithm 48 cp_ml_matrixVectorNTT
IPP_OWN_DEFN(IppStatus,
             cp_ml_expandMatrixMultiplyVectorNTT,
             (const Ipp8u* rho, IppPoly* v, IppPoly* out, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts = ippStsErr;

    Ipp8u l = mldsaCtx->params.l;
    Ipp8u k = mldsaCtx->params.k;
    for (Ipp8u r = 0; r < k; r++) {
        for (Ipp32u idx = 0; idx < CP_ML_N; idx++) {
            out[r].values[idx] = 0;
        }
    }
    /* Multi-buffer approach */
#if (_IPP32E >= _IPP32E_K0)
    /* Prepare rho for the multi-buffer processing */
    Ipp8u rho_j_i[4][34];
    CopyBlock(rho, rho_j_i[0], 32);
    CopyBlock(rho, rho_j_i[1], 32);
    CopyBlock(rho, rho_j_i[2], 32);
    CopyBlock(rho, rho_j_i[3], 32);

    Ipp8u nBuffs    = 4;
    Ipp8u remainder = (Ipp8u)((k * l) & (nBuffs - 1));
    Ipp8u i         = 0;
    IppPoly temp[4];
    for (; i < k * l - remainder; i += nBuffs) {
        Ipp8u r[4];
        Ipp8u s[4];
        for (Ipp8u j = 0; j < nBuffs; j++) {
            Ipp8u ij = i + j;
            r[j]     = ij / l;
            s[j]     = ij - (r[j] * l);

            rho_j_i[j][32] = s[j];
            rho_j_i[j][33] = r[j];
        }

        sts = cp_ml_rejNTTPoly_MB4(rho_j_i[0], rho_j_i[1], rho_j_i[2], rho_j_i[3], nBuffs, temp);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        /* Postprocessing */
        for (Ipp8u j = 0; j < nBuffs; j++) {
            cp_ml_multiplyNTT(temp + j, v + s[j], temp + j);
            cp_ml_addNTT(out + r[j], temp + j, out + r[j]);
        }
    }

    // process remainder
    if (remainder != 0) {
        nBuffs = remainder;
        for (Ipp8u j = 0; j < nBuffs; j++) {
            Ipp8u ij = i + j;
            Ipp8u r  = ij / l;
            Ipp8u s  = ij - (r * l);

            rho_j_i[j][32] = s;
            rho_j_i[j][33] = r;
        }

        sts = cp_ml_rejNTTPoly_MB4(rho_j_i[0], rho_j_i[1], rho_j_i[2], rho_j_i[3], nBuffs, temp);
        IPP_BADARG_RET((sts != ippStsNoErr), sts);
        /* Postprocessing */
        for (Ipp8u j = 0; j < nBuffs; j++) {
            cp_ml_multiplyNTT(temp + j, v + rho_j_i[j][32], temp + j);
            cp_ml_addNTT(out + rho_j_i[j][33], temp + j, out + rho_j_i[j][33]);
        }
    }

#else
    Ipp8u rho_[34];
    CopyBlock(rho, rho_, 32);

    IppPoly temp;
    for (Ipp8u r = 0; r < k; r++) {
        for (Ipp8u s = 0; s < l; s++) {
            rho_[32] = s;
            rho_[33] = r;

            sts = cp_ml_rejNTTPoly(rho_, &temp, mldsaCtx);
            IPP_BADARG_RET((sts != ippStsNoErr), sts);

            cp_ml_multiplyNTT(&temp, v + s, &temp);
            cp_ml_addNTT(out + r, &temp, out + r);
        }
    }
    PurgeBlock(rho_, sizeof(rho_)); // zeroize secrets
#endif /* #if (_IPP32E >= _IPP32E_K0) */
    return sts;
}
