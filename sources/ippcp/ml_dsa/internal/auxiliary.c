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
        Ipp8u shifted_i = (Ipp8u)(i + (Ipp8u)(CP_ML_N - mldsaCtx->params.tau));
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
            PurgeBlock(s, sizeof(s));                 // zeroize secrets
            PurgeBlock(c->values, sizeof(c->values)); // zeroize secrets
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
#if (_IPP32E >= _IPP32E_L9)

#define CP_ML_DSA_SAMPLENTT_BUFF_SIZE (258)

/* 258 bytes = 86 three-byte triples per squeezed block. */
#define CP_ML_DSA_SAMPLENTT_TRIPLES (CP_ML_DSA_SAMPLENTT_BUFF_SIZE / 3)

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

    Ipp8u s[4][CP_ML_DSA_SAMPLENTT_BUFF_SIZE];
    /* Squeeze the first big block unconditionally */
    cp_SHA3_SHAKE128_SqueezeMB4(s[0], s[1], s[2], s[3], CP_ML_DSA_SAMPLENTT_BUFF_SIZE, &state_mb4);
    /* Looping index is separate for each buffer */
    Ipp16u j[4]    = { 0, 0, 0, 0 };
    Ipp16u iter    = 0;
    Ipp32s allDone = 0;

    /* Phase-split rejection sampling: within each squeezed block, phase 1 decodes all 86
       triples per buffer into candidate + accept arrays (branch-light, auto-vectorizes),
       phase 2 compacts accepted candidates into the output. Byte consumption per buffer is
       identical to the per-triple loop (each buffer decodes its own stream in order), so the
       coefficient sequence — and the KAT — is unchanged. */
    while (!allDone && iter < CP_ML_DSA_MAX_REJ_NTT_POLY_ITERATIONS) {
        for (Ipp32s buf = 0; buf < numBuffers; buf++) {
            if (j[buf] >= 256) {
                continue;
            }
            Ipp32s cand[CP_ML_DSA_SAMPLENTT_TRIPLES];
            Ipp8u accept[CP_ML_DSA_SAMPLENTT_TRIPLES];
            const Ipp8u* p = s[buf];
            for (Ipp32u t = 0; t < CP_ML_DSA_SAMPLENTT_TRIPLES; t++) {
                cand[t]   = cp_ml_coeffFromThreeBytes(p[3 * t], p[3 * t + 1], p[3 * t + 2]);
                accept[t] = (Ipp8u)(cand[t] != -1);
            }
            for (Ipp32u t = 0; t < CP_ML_DSA_SAMPLENTT_TRIPLES && j[buf] < 256; t++) {
                if (accept[t]) {
                    a[buf].values[j[buf]] = cand[t];
                    j[buf]++;
                }
            }
        }
        /* refill: one shared 4-way squeeze feeds all buffers */
        allDone = 1;
        for (Ipp32s buf = 0; buf < numBuffers; buf++) {
            if (j[buf] < 256) {
                allDone = 0;
            }
        }
        if (!allDone) {
            cp_SHA3_SHAKE128_SqueezeMB4(s[0],
                                        s[1],
                                        s[2],
                                        s[3],
                                        CP_ML_DSA_SAMPLENTT_BUFF_SIZE,
                                        &state_mb4);
        }
        iter = (Ipp16u)(iter + CP_ML_DSA_SAMPLENTT_TRIPLES);
    }
    /* Release locally used storage */
    PurgeBlock(j, sizeof(j));
    PurgeBlock(state_buffer_mb4, sizeof(state_buffer_mb4));
    for (Ipp32s i = 0; i < 4; i++) {
        PurgeBlock(s[i], CP_ML_DSA_SAMPLENTT_BUFF_SIZE);
    }

    // Failure = budget exhausted before all buffers filled. Gate on allDone, not iter: the
    // phase-split advances iter by a whole block per round, so on success iter can exceed the
    // per-triple cap while every buffer is complete (allDone == 1). The cap
    // (CP_ML_DSA_MAX_REJ_NTT_POLY_ITERATIONS = 299, ml_dsa.h) is checked before each block,
    // so the effective budget is 4 * 86 = 344 triples. A larger budget only lowers the
    // already negligible failure rate.
    if (!allDone) {
        // Matrix A is public, so this is hygiene rather than secret erasure, but the loop
        // above fills a[0..numBuffers-1] and the wipe should cover the same range.
        for (Ipp32s buf = 0; buf < numBuffers; buf++) {
            PurgeBlock(a[buf].values, sizeof(a[buf].values));
        }
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

        /* phase-split: vectorizable decode of the 32 triples, then scalar compaction */
        Ipp32s cand[CP_ML_DSA_N_BLOCKS];
        Ipp8u accept[CP_ML_DSA_N_BLOCKS];
        for (int idx = 0; idx < CP_ML_DSA_N_BLOCKS; ++idx) {
            cand[idx]   = cp_ml_coeffFromThreeBytes(s[3 * idx], s[3 * idx + 1], s[3 * idx + 2]);
            accept[idx] = (Ipp8u)(cand[idx] != -1);
        }
        for (int idx = 0; idx < CP_ML_DSA_N_BLOCKS && j < (Ipp16u)CP_ML_N; ++idx) {
            if (accept[idx]) {
                a->values[j] = cand[idx];
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
        PurgeBlock(a->values, sizeof(a->values)); // zeroize secrets
        return ippStsMLDSAMaxIterations;
    }
    return sts;
}
#endif /* #if (_IPP32E >= _IPP32E_L9) */

// Algorithm 31 RejBoundedPoly(rho)

#if (_IPP32E >= _IPP32E_L9)

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

    /* 256 bytes = 512 half-byte candidates (low nibble then high nibble per byte). */
#define CP_ML_DSA_BOUNDED_CANDS (2 * CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE)
    Ipp8u z[4][CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE];
    /* Squeeze the first big block unconditionally */
    cp_SHA3_SHAKE256_SqueezeMB4(z[0],
                                z[1],
                                z[2],
                                z[3],
                                CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE,
                                &state_mb4);
    /* Looping index is separate for each buffer */
    Ipp16u j[4]    = { 0, 0, 0, 0 };
    Ipp16u iter    = 0;
    Ipp32s allDone = 0;
    Ipp8u eta      = mldsaCtx->params.eta;

    /* Phase-split (same idea as cp_ml_rejNTTPoly_MB4): phase 1 decodes all 512 nibble
       candidates per buffer into cand + accept (order preserved: low nibble of byte b at
       index 2b, high nibble at 2b+1), phase 2 compacts. Identical coefficient sequence and
       byte consumption -> KAT-exact. coeffFromHalfByte returns -100 on reject.
       cand holds decoded s1/s2 coefficients, so it is declared here and zeroized below. */
    Ipp8s cand[CP_ML_DSA_BOUNDED_CANDS];
    Ipp8u accept[CP_ML_DSA_BOUNDED_CANDS];
    while (!allDone && iter < CP_ML_DSA_MAX_REJ_BOUNDED_POLY_ITERATIONS) {
        for (Ipp32s buf = 0; buf < numBuffers; buf++) {
            if (j[buf] >= (Ipp16u)CP_ML_N) {
                continue;
            }
            const Ipp8u* zb = z[buf];
            for (Ipp32u b = 0; b < CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE; b++) {
                Ipp8s c0          = cp_ml_coeffFromHalfByte(zb[b] & 15, eta);
                Ipp8s c1          = cp_ml_coeffFromHalfByte(zb[b] >> 4, eta);
                cand[2 * b]       = c0;
                accept[2 * b]     = (Ipp8u)(c0 != -100);
                cand[2 * b + 1]   = c1;
                accept[2 * b + 1] = (Ipp8u)(c1 != -100);
            }
            for (Ipp32u t = 0; t < CP_ML_DSA_BOUNDED_CANDS && j[buf] < (Ipp16u)CP_ML_N; t++) {
                if (accept[t]) {
                    s[buf].values[j[buf]] = cand[t];
                    j[buf]++;
                }
            }
        }
        allDone = 1;
        for (Ipp32s buf = 0; buf < numBuffers; buf++) {
            if (j[buf] < (Ipp16u)CP_ML_N) {
                allDone = 0;
            }
        }
        if (!allDone) {
            cp_SHA3_SHAKE256_SqueezeMB4(z[0],
                                        z[1],
                                        z[2],
                                        z[3],
                                        CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE,
                                        &state_mb4);
        }
        iter = (Ipp16u)(iter + CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE);
    }
    /* Release locally used storage */
    PurgeBlock(j, sizeof(j));
    PurgeBlock(cand, sizeof(cand));
    PurgeBlock(accept, sizeof(accept));
    PurgeBlock(state_buffer_mb4, sizeof(state_buffer_mb4));
    for (Ipp32s i = 0; i < 4; i++) {
        PurgeBlock(z[i], CP_ML_DSA_BOUNDED_POLY_BUFF_SIZE);
    }

    // Failure = budget exhausted before all buffers filled. Gate on allDone, not iter (see
    // cp_ml_rejNTTPoly_MB4): the phase-split advances iter by a whole block per round. The
    // cap (CP_ML_DSA_MAX_REJ_BOUNDED_POLY_ITERATIONS = 482 bytes, ml_dsa.h) is checked before
    // each block, so the effective budget is 2 * 256 = 512 bytes.
    if (!allDone) {
        // The loop above fills s[0..numBuffers-1], so purge every buffer, not just s[0].
        for (Ipp32s buf = 0; buf < numBuffers; buf++) {
            PurgeBlock(s[buf].values, sizeof(s[buf].values)); // zeroize secrets
        }
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
    Ipp8u eta   = mldsaCtx->params.eta;
    Ipp16u iter = 0;
    /* cand holds decoded s1/s2 coefficients, so it is declared here and zeroized below. */
    Ipp8s cand[2 * CP_ML_DSA_N_BLOCKS];
    Ipp8u accept[2 * CP_ML_DSA_N_BLOCKS];
    while (j < CP_ML_N && iter < CP_ML_DSA_MAX_REJ_BOUNDED_POLY_ITERATIONS) {
        sts = ippsHashSqueeze_rmf(z, CP_ML_DSA_N_BLOCKS, hash_state);
        if (sts != ippStsNoErr) {
            PurgeBlock(z, sizeof(z)); // zeroize secrets
            PurgeBlock(cand, sizeof(cand));
            PurgeBlock(accept, sizeof(accept));
            return sts;
        }

        /* phase-split: decode 2*32 nibble candidates (low at 2i, high at 2i+1), then compact */
        for (int i = 0; i < CP_ML_DSA_N_BLOCKS; i++) {
            Ipp8s c0          = cp_ml_coeffFromHalfByte(z[i] & 15, eta);
            Ipp8s c1          = cp_ml_coeffFromHalfByte(z[i] >> 4, eta);
            cand[2 * i]       = c0;
            accept[2 * i]     = (Ipp8u)(c0 != -100);
            cand[2 * i + 1]   = c1;
            accept[2 * i + 1] = (Ipp8u)(c1 != -100);
        }
        for (int t = 0; t < 2 * CP_ML_DSA_N_BLOCKS && j < (Ipp16u)CP_ML_N; t++) {
            if (accept[t]) {
                a->values[j] = cand[t];
                j++;
            }
        }
        iter++;
    }
    PurgeBlock(z, sizeof(z)); // zeroize secrets
    PurgeBlock(cand, sizeof(cand));
    PurgeBlock(accept, sizeof(accept));

    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage, hash_size + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);

    if (iter >= CP_ML_DSA_MAX_REJ_BOUNDED_POLY_ITERATIONS) {
        PurgeBlock(a->values, sizeof(a->values)); // zeroize secrets
        return ippStsMLDSAMaxIterations;
    }

    return sts;
}
#endif /* #if (_IPP32E >= _IPP32E_L9) */

// Algorithm 32 ExpandA(rho)
IPP_OWN_DEFN(IppStatus,
             cp_ml_expandA,
             (const Ipp8u* rho, IppPoly* matrixA, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts = ippStsErr;
    const Ipp8u k = mldsaCtx->params.k;
    const Ipp8u l = mldsaCtx->params.l;

    /* Multi-buffer approach */
#if (_IPP32E >= _IPP32E_L9)
    /* Prepare rho for the multi-buffer processing */
    Ipp8u rho_j_i[4][34];
    CopyBlock(rho, rho_j_i[0], 32);
    CopyBlock(rho, rho_j_i[1], 32);
    CopyBlock(rho, rho_j_i[2], 32);
    CopyBlock(rho, rho_j_i[3], 32);

    Ipp8u nBuffs    = 4;
    Ipp8u remainder = (Ipp8u)(k * l & (nBuffs - 1));
    Ipp8u i         = 0;
    for (; i < k * l - remainder; i = (Ipp8u)(i + nBuffs)) {
        for (Ipp8u j = 0; j < nBuffs; j++) {
            Ipp8u ij = (Ipp8u)(i + j);
            Ipp8u r  = ij / l;
            Ipp8u s  = (Ipp8u)(ij - (r * l));

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
            Ipp8u ij = (Ipp8u)(i + j);
            Ipp8u r  = ij / l;
            Ipp8u s  = (Ipp8u)(ij - (r * l));

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
#endif /* #if (_IPP32E >= _IPP32E_L9) */
    return sts;
}

// Algorithm 33 ExpandS(rho)
/* seed buffer size: 64-byte rho' seed followed by a 2-byte index */
#define CP_ML_DSA_EXPANDS_SEED_SIZE (66)
IPP_OWN_DEFN(IppStatus,
             cp_ml_expandS,
             (Ipp8u * rho, IppPoly* s1, IppPoly* s2, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts = ippStsErr;

    const Ipp8u k = mldsaCtx->params.k;
    const Ipp8u l = mldsaCtx->params.l;

    /* Multi-buffer approach */
#if (_IPP32E >= _IPP32E_L9)
    /* Prepare rho for the multi-buffer processing */
    Ipp8u rho_j_i[4][CP_ML_DSA_EXPANDS_SEED_SIZE];
    CopyBlock(rho, rho_j_i[0], 64);
    CopyBlock(rho, rho_j_i[1], 64);
    CopyBlock(rho, rho_j_i[2], 64);
    CopyBlock(rho, rho_j_i[3], 64);

    Ipp8u nIters = (Ipp8u)((l + 3) / 4);
    Ipp8u nBuffs = 4;

    // process 1st loop over l
    for (Ipp8u iter = 0; iter < nIters; iter++) {
        for (Ipp8u i = 0; i < nBuffs; i++) {
            rho_j_i[i][64] = (Ipp8u)(i + iter * 4);
            rho_j_i[i][65] = 0;
        }

        sts = cp_ml_rejBoundedPoly_MB4(rho_j_i[0],
                                       rho_j_i[1],
                                       rho_j_i[2],
                                       rho_j_i[3],
                                       nBuffs,
                                       s1 + iter * 4,
                                       mldsaCtx);
        if (sts != ippStsNoErr)
            goto exit;

        nBuffs = (Ipp8u)(l - nBuffs);
    }

    // process 2nd loop over k
    nIters = (Ipp8u)((k + 3) / 4);
    nBuffs = 4;
    for (Ipp8u iter = 0; iter < nIters; iter++) {
        for (Ipp8u i = 0; i < nBuffs; i++) {
            rho_j_i[i][64] = (Ipp8u)(i + iter * 4 + l);
            rho_j_i[i][65] = 0;
        }

        sts = cp_ml_rejBoundedPoly_MB4(rho_j_i[0],
                                       rho_j_i[1],
                                       rho_j_i[2],
                                       rho_j_i[3],
                                       nBuffs,
                                       s2 + iter * 4,
                                       mldsaCtx);
        if (sts != ippStsNoErr)
            goto exit;
        nBuffs = (Ipp8u)(k - nBuffs);
    }

#else

    Ipp8u rho_[CP_ML_DSA_EXPANDS_SEED_SIZE];
    CopyBlock(rho, rho_, 64);
    for (Ipp8u r = 0; r < l; r++) {
        rho_[64] = r;
        rho_[65] = 0;
        sts      = cp_ml_rejBoundedPoly(rho_, s1 + r, mldsaCtx);
        if (sts != ippStsNoErr)
            goto exit;
    }

    for (Ipp8u r = 0; r < k; r++) {
        rho_[64] = (Ipp8u)(r + l);
        rho_[65] = 0;
        sts      = cp_ml_rejBoundedPoly(rho_, s2 + r, mldsaCtx);
        if (sts != ippStsNoErr)
            goto exit;
    }
#endif /* #if (_IPP32E >= _IPP32E_L9) */

exit:
    /* Release locally used storage */
#if (_IPP32E >= _IPP32E_L9)
    for (Ipp32s i = 0; i < 4; i++) {
        PurgeBlock(rho_j_i[i], CP_ML_DSA_EXPANDS_SEED_SIZE); // zeroize secret seed
    }
#else
    PurgeBlock(rho_, sizeof(rho_)); // zeroize secret seed
#endif
    return sts;
}

// Algorithm 34 ExpandMask(rho, mu)
IPP_OWN_DEFN(IppStatus,
             cp_ml_expandMask,
             (Ipp8u * rho, Ipp32u mu, IppPoly* out, IppsMLDSAState* mldsaCtx))
{
    IppStatus sts             = ippStsErr;
    Ipp32s gamma_1            = mldsaCtx->params.gamma_1;
    Ipp8u c                   = (Ipp8u)(1 + cp_ml_bitlen((Ipp32u)(gamma_1 - 1)));
    Ipp32u bitlen_ab          = cp_ml_bitlen((Ipp32u)(2 * gamma_1 - 1));
    const Ipp8u l             = mldsaCtx->params.l;
    _cpMLDSAStorage* pStorage = &mldsaCtx->storage;

#if (_IPP32E >= _IPP32E_L9)
    /* Multi-buffer approach */
    Ipp32u vlen = (Ipp32u)(32 * c);
    Ipp8u* v    = cp_mlStorageAllocate(pStorage, (Ipp32s)(4 * vlen) + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((v == NULL), ippStsMemAllocErr);

    Ipp8u rho_j_i[4][66];
    CopyBlock(rho, rho_j_i[0], 64);
    CopyBlock(rho, rho_j_i[1], 64);
    CopyBlock(rho, rho_j_i[2], 64);
    CopyBlock(rho, rho_j_i[3], 64);

    Ipp8u state_buffer_mb4[STATE_x4_SIZE];
    cpSHA3_SHAKE256Ctx_mb4 state_mb4;
    state_mb4.ctx = state_buffer_mb4;

    Ipp8u nIters = (Ipp8u)((l + 3) / 4);
    Ipp8u nBuffs = 4;
    for (Ipp8u iter = 0; iter < nIters; iter++) {
        for (Ipp8u i = 0; i < nBuffs; i++) {
            Ipp32u idx     = mu + (Ipp32u)(i + iter * 4);
            rho_j_i[i][64] = idx & 0xFF;
            rho_j_i[i][65] = (idx >> 8) & 0xFF;
        }

        cp_SHA3_SHAKE256_InitMB4(&state_mb4);
        cp_SHA3_SHAKE256_AbsorbMB4(&state_mb4, rho_j_i[0], rho_j_i[1], rho_j_i[2], rho_j_i[3], 66);
        cp_SHA3_SHAKE256_FinalizeMB4(&state_mb4);
        cp_SHA3_SHAKE256_SqueezeMB4(v, v + vlen, v + 2 * vlen, v + 3 * vlen, vlen, &state_mb4);

        for (Ipp8u i = 0; i < nBuffs; i++) {
            cp_ml_bitUnpack(v + i * vlen, (Ipp32s)gamma_1, bitlen_ab, out + iter * 4 + i);
        }

        nBuffs = (Ipp8u)(l - nBuffs);
    }

    /* Release locally used storage */
    for (Ipp32s i = 0; i < 4; i++) {
        PurgeBlock(rho_j_i[i], 66);
    }
    PurgeBlock(state_buffer_mb4, sizeof(state_buffer_mb4));
    sts = cp_mlStorageRelease(pStorage, (Ipp32s)(4 * vlen) + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((sts != ippStsNoErr), sts);
    return ippStsNoErr;
#else
    IppsHashMethod shake256_method;
    Ipp8u* v = cp_mlStorageAllocate(pStorage, 32 * c + CP_ML_ALIGNMENT);
    IPP_BADARG_RET((v == NULL), ippStsMemAllocErr);

    Ipp8u rho_[66];
    CopyBlock(rho, rho_, 64);

    for (Ipp8u r = 0; r < l; r++) {
        rho_[64] = (mu + r) & 0xFF;
        rho_[65] = ((mu + r) >> 8) & 0xFF;
        sts      = ippsHashMethodSet_SHAKE256(&shake256_method, (8 * 32 * c));
        if (sts != ippStsNoErr)
            goto exit;
        sts = ippsHashMessage_rmf(rho_, 66, v, &shake256_method);
        if (sts != ippStsNoErr)
            goto exit;
        cp_ml_bitUnpack(v, (Ipp32s)gamma_1, bitlen_ab, out + r);
    }
    /* Release locally used storage */
    sts = cp_mlStorageRelease(pStorage, 32 * c + CP_ML_ALIGNMENT);

exit:
    PurgeBlock(rho_, sizeof(rho_)); // zeroize secret seed
    return sts;
#endif /* #if (_IPP32E >= _IPP32E_L9) */
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
#if (_IPP32E >= _IPP32E_L9)
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
    for (; i < k * l - remainder; i = (Ipp8u)(i + nBuffs)) {
        Ipp8u r[4];
        Ipp8u s[4];
        for (Ipp8u j = 0; j < nBuffs; j++) {
            Ipp8u ij = (Ipp8u)(i + j);
            r[j]     = ij / l;
            s[j]     = (Ipp8u)(ij - (r[j] * l));

            rho_j_i[j][32] = s[j];
            rho_j_i[j][33] = r[j];
        }

        sts = cp_ml_rejNTTPoly_MB4(rho_j_i[0], rho_j_i[1], rho_j_i[2], rho_j_i[3], nBuffs, temp);
        if (sts != ippStsNoErr)
            goto exit;
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
            Ipp8u ij = (Ipp8u)(i + j);
            Ipp8u r  = ij / l;
            Ipp8u s  = (Ipp8u)(ij - (r * l));

            rho_j_i[j][32] = s;
            rho_j_i[j][33] = r;
        }

        sts = cp_ml_rejNTTPoly_MB4(rho_j_i[0], rho_j_i[1], rho_j_i[2], rho_j_i[3], nBuffs, temp);
        if (sts != ippStsNoErr)
            goto exit;
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
            if (sts != ippStsNoErr)
                goto exit;

            cp_ml_multiplyNTT(&temp, v + s, &temp);
            cp_ml_addNTT(out + r, &temp, out + r);
        }
    }
#endif /* #if (_IPP32E >= _IPP32E_L9) */

exit:
    /* zeroize secret NTT products */
#if (_IPP32E >= _IPP32E_L9)
    PurgeBlock(temp, sizeof(temp));
#else
    PurgeBlock(&temp, sizeof(temp));
    PurgeBlock(rho_, sizeof(rho_));
#endif
    return sts;
}
