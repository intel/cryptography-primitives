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

#ifdef IPPCP_FIPS_MODE

#ifndef IPPCP_PREVIEW_ML_DSA
#define IPPCP_PREVIEW_ML_DSA (1)
#endif

#include "ippcp.h"
#include "owndefs.h"
#include "dispatcher.h"

// FIPS selftests are not processed by dispatcher.
// Prevent several copies of the same functions.
#ifdef _IPP_DATA

#include "ippcp/fips_cert.h"
#include "fips_cert_internal/common.h"
#include "fips_cert_internal/mldsa_kat_common.h"

IPPFUN(fips_test_status, fips_selftest_ippsMLDSA_Sign_get_size_data_buff, (int* pDataBuffSize))
{
    IPP_BADARG_RET((NULL == pDataBuffSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts  = ippStsNoErr;
    int total_size = 0;
    int tmp_size   = 0;

    /* Get ML-DSA state size */
    sts = ippsMLDSA_GetSize(&tmp_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    total_size += tmp_size + IPPCP_MLDSA_ALIGNMENT;

    /* Get ML-DSA-44 signature size */
    IppsMLDSAInfo info;
    sts = ippsMLDSA_GetInfo(&info, ML_DSA_44);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    total_size += info.signatureSize + IPPCP_MLDSA_ALIGNMENT;

    *pDataBuffSize = total_size;
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsMLDSA_Verify_get_size_data_buff, (int* pDataBuffSize))
{
    IPP_BADARG_RET((NULL == pDataBuffSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int tmp_size  = 0;

    /* Get ML-DSA state size only */
    sts = ippsMLDSA_GetSize(&tmp_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    *pDataBuffSize = tmp_size + IPPCP_MLDSA_ALIGNMENT;
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsMLDSA_Verify_Mu_get_size_data_buff, (int* pDataBuffSize))
{
    return fips_selftest_ippsMLDSA_Verify_get_size_data_buff(pDataBuffSize);
}

IPPFUN(fips_test_status, fips_selftest_ippsMLDSA_KeyGen_get_size_data_buff, (int* pDataBuffSize))
{
    IPP_BADARG_RET((NULL == pDataBuffSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts  = ippStsNoErr;
    int total_size = 0;
    int tmp_size   = 0;

    /* Get ML-DSA state size */
    sts = ippsMLDSA_GetSize(&tmp_size);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }
    total_size += tmp_size + IPPCP_MLDSA_ALIGNMENT;

    /* Get maximum key sizes across all parameter sets */
    IppsMLDSAInfo info;
    int max_pk_size = 0;
    int max_sk_size = 0;

    IppsMLDSAParamSet param_sets[] = { ML_DSA_44, ML_DSA_65, ML_DSA_87 };
    for (int i = 0; i < 3; i++) {
        sts = ippsMLDSA_GetInfo(&info, param_sets[i]);
        if (sts != ippStsNoErr) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
        max_pk_size = IPP_MAX(max_pk_size, info.publicKeySize);
        max_sk_size = IPP_MAX(max_sk_size, info.privateKeySize);
    }

    /* Add space for maximum key sizes */
    total_size += max_pk_size + IPPCP_MLDSA_ALIGNMENT;
    total_size += max_sk_size + IPPCP_MLDSA_ALIGNMENT;

    *pDataBuffSize = total_size;
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status,
       fips_selftest_ippsMLDSA_Sign_get_size,
       (int* pBufferSize, Ipp8u* pDataBuff))
{
    IPP_BADARG_RET((NULL == pDataBuff) || (NULL == pBufferSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int tmp_size  = 0;

    /* Find maximum message length across all test vectors */
    int max_msg_len = 0;
    int num_vectors = sizeof(sign_kat_vectors) / sizeof(sign_kat_vectors[0]);
    for (int i = 0; i < num_vectors; i++) {
        max_msg_len = IPP_MAX(max_msg_len, (int)sign_kat_vectors[i].msg_len);
    }

    /* Initialize ML-DSA state with maximum message length */
    Ipp8u* pLocDataBuff    = (IPP_ALIGNED_PTR(pDataBuff, IPPCP_MLDSA_ALIGNMENT));
    IppsMLDSAState* pState = (IppsMLDSAState*)pLocDataBuff;

    sts = ippsMLDSA_Init(pState, max_msg_len, ML_DSA_44);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Get Sign buffer size for maximum case */
    sts = ippsMLDSA_SignBufferGetSize(&tmp_size, pState);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    *pBufferSize = tmp_size + IPPCP_MLDSA_ALIGNMENT;
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status,
       fips_selftest_ippsMLDSA_Verify_get_size,
       (int* pBufferSize, Ipp8u* pDataBuff))
{
    IPP_BADARG_RET((NULL == pDataBuff) || (NULL == pBufferSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int tmp_size  = 0;

    /* Find maximum message length across all verify test vectors */
    Ipp32s max_msg_len = 0;
    int num_vectors    = sizeof(verify_kat_vectors) / sizeof(verify_kat_vectors[0]);
    for (int i = 0; i < num_vectors; i++) {
        max_msg_len = IPP_MAX(max_msg_len, verify_kat_vectors[i].msg_len);
    }

    /* Initialize ML-DSA state with maximum message length */
    Ipp8u* pLocDataBuff    = (IPP_ALIGNED_PTR(pDataBuff, IPPCP_MLDSA_ALIGNMENT));
    IppsMLDSAState* pState = (IppsMLDSAState*)pLocDataBuff;

    sts = ippsMLDSA_Init(pState, max_msg_len, ML_DSA_44);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Get Verify buffer size for maximum case */
    sts = ippsMLDSA_VerifyBufferGetSize(&tmp_size, pState);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    *pBufferSize = tmp_size + IPPCP_MLDSA_ALIGNMENT;
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status,
       fips_selftest_ippsMLDSA_Verify_Mu_get_size,
       (int* pBufferSize, Ipp8u* pDataBuff))
{
    IPP_BADARG_RET((NULL == pDataBuff) || (NULL == pBufferSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts = ippStsNoErr;
    int tmp_size  = 0;

    Ipp8u* pLocDataBuff    = (IPP_ALIGNED_PTR(pDataBuff, IPPCP_MLDSA_ALIGNMENT));
    IppsMLDSAState* pState = (IppsMLDSAState*)pLocDataBuff;

    sts = ippsMLDSA_Init(pState, 1, ML_DSA_44);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    sts = ippsMLDSA_Verify_Mu_BufferGetSize(&tmp_size, pState);
    if (sts != ippStsNoErr) {
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    int hashMethodSize = 0;
    ippsHashMethodGetSize(&hashMethodSize);

    int max_msg_len = 0;
    int num_vectors = sizeof(verify_kat_vectors) / sizeof(verify_kat_vectors[0]);
    for (int i = 0; i < num_vectors; i++) {
        if (verify_kat_vectors[i].msg_len > max_msg_len) {
            max_msg_len = verify_kat_vectors[i].msg_len;
        }
    }
    int max_M_len = 64 + 2 + max_msg_len;

    *pBufferSize = tmp_size + IPPCP_MLDSA_ALIGNMENT + hashMethodSize + IPPCP_MLDSA_ALIGNMENT +
                   max_M_len + IPPCP_MLDSA_ALIGNMENT;
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status,
       fips_selftest_ippsMLDSA_KeyGen_get_size,
       (int* pBufferSize, Ipp8u* pDataBuff))
{
    IPP_BADARG_RET((NULL == pDataBuff) || (NULL == pBufferSize), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);

    IppStatus sts  = ippStsNoErr;
    int total_size = 0;
    int tmp_size   = 0;

    /* Test all 3 parameter sets */
    IppsMLDSAParamSet param_sets[] = { ML_DSA_44, ML_DSA_65, ML_DSA_87 };

    for (int i = 0; i < 3; i++) {
        /* Initialize ML-DSA state for this parameter set */
        Ipp8u* pLocDataBuff    = (IPP_ALIGNED_PTR(pDataBuff, IPPCP_MLDSA_ALIGNMENT));
        IppsMLDSAState* pState = (IppsMLDSAState*)pLocDataBuff;

        sts = ippsMLDSA_Init(pState, 1, param_sets[i]); // Use minimal message length
        if (sts != ippStsNoErr) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        /* Get KeyGen buffer size for this parameter set */
        sts = ippsMLDSA_KeyGenBufferGetSize(&tmp_size, pState);
        if (sts != ippStsNoErr) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
        total_size = IPP_MAX(total_size, tmp_size);
    }

    *pBufferSize = total_size + IPPCP_MLDSA_ALIGNMENT;
    return IPPCP_ALGO_SELFTEST_OK;
}

IPPFUN(fips_test_status, fips_selftest_ippsMLDSA_Sign, (Ipp8u * pBuffer, Ipp8u* pDataBuff))
{
    IppStatus sts                = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    /* Internal memory allocation feature */
    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if (pBuffer == NULL || pDataBuff == NULL) {
        internalMemMgm      = 1;
        int dataBuffSize    = 0;
        int scratchBuffSize = 0;

        test_result = fips_selftest_ippsMLDSA_Sign_get_size_data_buff(&dataBuffSize);
        if (test_result != IPPCP_ALGO_SELFTEST_OK) {
            return test_result;
        }
        pDataBuff = malloc((size_t)dataBuffSize);
        if (pDataBuff == NULL) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        test_result = fips_selftest_ippsMLDSA_Sign_get_size(&scratchBuffSize, pDataBuff);
        if (test_result != IPPCP_ALGO_SELFTEST_OK) {
            MEMORY_FREE(pDataBuff, internalMemMgm)
            return test_result;
        }
        pBuffer = malloc((size_t)scratchBuffSize);
        if (pBuffer == NULL) {
            MEMORY_FREE(pDataBuff, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
    }
#else
    IPP_BADARG_RET((NULL == pBuffer) || (NULL == pDataBuff), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    /* Get sizes for buffer navigation */
    int stateSize = 0;
    sts           = ippsMLDSA_GetSize(&stateSize);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    IppsMLDSAInfo info;
    sts = ippsMLDSA_GetInfo(&info, ML_DSA_44);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    /* Navigate Sign buffer layout: [State] → [Signature] */
    Ipp8u* pLocDataBuff    = (IPP_ALIGNED_PTR(pDataBuff, IPPCP_MLDSA_ALIGNMENT));
    IppsMLDSAState* pState = (IppsMLDSAState*)pLocDataBuff;
    pLocDataBuff += stateSize;

    pLocDataBuff      = (IPP_ALIGNED_PTR(pLocDataBuff, IPPCP_MLDSA_ALIGNMENT));
    Ipp8u* pSignature = pLocDataBuff;

    /* Get scratch buffer */
    Ipp8u* pScratchBuffer = (IPP_ALIGNED_PTR(pBuffer, IPPCP_MLDSA_ALIGNMENT));

    /* Test all sign vectors */
    int num_vectors = sizeof(sign_kat_vectors) / sizeof(sign_kat_vectors[0]);
    for (int vector_idx = 0; vector_idx < num_vectors; vector_idx++) {
        const MLDSASignKAT* kat = &sign_kat_vectors[vector_idx];

        /* Initialize ML-DSA state for this vector */
        sts = ippsMLDSA_Init(pState, kat->msg_len, ML_DSA_44);
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        /* Sign message using KAT private key with deterministic RNG */
        sts = ippsMLDSA_Sign(kat->message,
                             kat->msg_len,
                             NULL, /* context */
                             0,    /* context length */
                             kat->private_key,
                             pSignature,
                             pState,
                             pScratchBuffer,
                             mldsa_kat_seed_supplier,
                             (void*)kat->rng_seed);
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        /* Compare generated signature with expected KAT value */
        int sigMatch = ippcp_is_mem_eq(kat->expected_signature,
                                       kat->sig_len,
                                       pSignature,
                                       (Ipp32u)info.signatureSize);
        if (sigMatch != 1) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_KAT_ERR;
        }
    }

    MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
    return test_result;
}

IPPFUN(fips_test_status, fips_selftest_ippsMLDSA_Verify, (Ipp8u * pBuffer, Ipp8u* pDataBuff))
{
    IppStatus sts                = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    /* Internal memory allocation feature */
    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if (pBuffer == NULL || pDataBuff == NULL) {
        internalMemMgm      = 1;
        int dataBuffSize    = 0;
        int scratchBuffSize = 0;

        test_result = fips_selftest_ippsMLDSA_Verify_get_size_data_buff(&dataBuffSize);
        if (test_result != IPPCP_ALGO_SELFTEST_OK) {
            return test_result;
        }
        pDataBuff = malloc((size_t)dataBuffSize);
        if (pDataBuff == NULL) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        test_result = fips_selftest_ippsMLDSA_Verify_get_size(&scratchBuffSize, pDataBuff);
        if (test_result != IPPCP_ALGO_SELFTEST_OK) {
            MEMORY_FREE(pDataBuff, internalMemMgm)
            return test_result;
        }
        pBuffer = malloc((size_t)scratchBuffSize);
        if (pBuffer == NULL) {
            MEMORY_FREE(pDataBuff, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
    }
#else
    IPP_BADARG_RET((NULL == pBuffer) || (NULL == pDataBuff), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    /* Navigate Verify buffer layout: [State] only */
    Ipp8u* pLocDataBuff    = (IPP_ALIGNED_PTR(pDataBuff, IPPCP_MLDSA_ALIGNMENT));
    IppsMLDSAState* pState = (IppsMLDSAState*)pLocDataBuff;

    /* Get scratch buffer */
    Ipp8u* pScratchBuffer = (IPP_ALIGNED_PTR(pBuffer, IPPCP_MLDSA_ALIGNMENT));

    /* Test all verify vectors */
    int num_vectors = sizeof(verify_kat_vectors) / sizeof(verify_kat_vectors[0]);
    for (int vector_idx = 0; vector_idx < num_vectors; vector_idx++) {
        const MLDSAVerifyKAT* kat = &verify_kat_vectors[vector_idx];

        /* Initialize ML-DSA state for this vector */
        sts = ippsMLDSA_Init(pState, kat->msg_len, ML_DSA_44);
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        /* Verify signature using KAT public key and signature */
        int isValid = 0;

        sts = ippsMLDSA_Verify(kat->message,
                               kat->msg_len,
                               NULL, /* context */
                               0,    /* context length */
                               kat->public_key,
                               kat->signature,
                               &isValid,
                               pState,
                               pScratchBuffer);
        if (sts != ippStsNoErr || isValid != 1) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_KAT_ERR;
        }
    }

    MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
    return test_result;
}

IPPFUN(fips_test_status, fips_selftest_ippsMLDSA_Verify_Mu, (Ipp8u * pBuffer, Ipp8u* pDataBuff))
{
    IppStatus sts                = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if (pBuffer == NULL || pDataBuff == NULL) {
        internalMemMgm      = 1;
        int dataBuffSize    = 0;
        int scratchBuffSize = 0;

        test_result = fips_selftest_ippsMLDSA_Verify_Mu_get_size_data_buff(&dataBuffSize);
        if (test_result != IPPCP_ALGO_SELFTEST_OK) {
            return test_result;
        }
        pDataBuff = malloc((size_t)dataBuffSize);
        if (pDataBuff == NULL) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        test_result = fips_selftest_ippsMLDSA_Verify_Mu_get_size(&scratchBuffSize, pDataBuff);
        if (test_result != IPPCP_ALGO_SELFTEST_OK) {
            MEMORY_FREE(pDataBuff, internalMemMgm)
            return test_result;
        }
        pBuffer = malloc((size_t)scratchBuffSize);
        if (pBuffer == NULL) {
            MEMORY_FREE(pDataBuff, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
    }
#else
    IPP_BADARG_RET((NULL == pBuffer) || (NULL == pDataBuff), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    Ipp8u* pLocDataBuff    = (IPP_ALIGNED_PTR(pDataBuff, IPPCP_MLDSA_ALIGNMENT));
    IppsMLDSAState* pState = (IppsMLDSAState*)pLocDataBuff;

    Ipp8u* pScratchBuffer = (IPP_ALIGNED_PTR(pBuffer, IPPCP_MLDSA_ALIGNMENT));

    int hashMethodSize = 0;
    ippsHashMethodGetSize(&hashMethodSize);
    IppsHashMethod* pShake256Method = (IppsHashMethod*)pScratchBuffer;
    pScratchBuffer += hashMethodSize;
    pScratchBuffer = (IPP_ALIGNED_PTR(pScratchBuffer, IPPCP_MLDSA_ALIGNMENT));

    sts = ippsHashMethodSet_SHAKE256(pShake256Method, 512);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    IppsMLDSAInfo info;
    sts = ippsMLDSA_GetInfo(&info, ML_DSA_44);
    if (sts != ippStsNoErr) {
        MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
        return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
    }

    int max_msg_len = 0;
    int num_vectors = sizeof(verify_kat_vectors) / sizeof(verify_kat_vectors[0]);
    for (int i = 0; i < num_vectors; i++) {
        if (verify_kat_vectors[i].msg_len > max_msg_len) {
            max_msg_len = verify_kat_vectors[i].msg_len;
        }
    }

    Ipp8u* pM_buffer = pScratchBuffer;
    pScratchBuffer += 64 + 2 + max_msg_len;
    pScratchBuffer = (IPP_ALIGNED_PTR(pScratchBuffer, IPPCP_MLDSA_ALIGNMENT));

    for (int vector_idx = 0; vector_idx < num_vectors; vector_idx++) {
        const MLDSAVerifyKAT* kat = &verify_kat_vectors[vector_idx];

        sts = ippsMLDSA_Init(pState, kat->msg_len, ML_DSA_44);
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        Ipp8u tr[64];
        sts = ippsHashMessage_rmf(kat->public_key, info.publicKeySize, tr, pShake256Method);
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        int M_len = 64 + 2 + kat->msg_len;
        Ipp8u* M_ = pM_buffer;
        for (int i = 0; i < 64; ++i)
            M_[i] = tr[i];
        M_[64] = 0;
        M_[65] = 0; /* Context length */
        for (int i = 0; i < kat->msg_len; ++i)
            M_[66 + i] = kat->message[i];

        Ipp8u mu[64];
        sts = ippsHashMessage_rmf(M_, M_len, mu, pShake256Method);
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        int isValid = 0;

        sts = ippsMLDSA_Verify_Mu(mu,
                                  kat->public_key,
                                  kat->signature,
                                  &isValid,
                                  pState,
                                  pScratchBuffer);
        if (sts != ippStsNoErr || isValid != 1) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_KAT_ERR;
        }
    }

    MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
    return test_result;
}

IPPFUN(fips_test_status, fips_selftest_ippsMLDSA_KeyGen, (Ipp8u * pBuffer, Ipp8u* pDataBuff))
{
    IppStatus sts                = ippStsNoErr;
    fips_test_status test_result = IPPCP_ALGO_SELFTEST_OK;

    /* Internal memory allocation feature */
    int internalMemMgm = 0;
#if IPPCP_SELFTEST_USE_MALLOC
    if (pBuffer == NULL || pDataBuff == NULL) {
        internalMemMgm      = 1;
        int dataBuffSize    = 0;
        int scratchBuffSize = 0;

        test_result = fips_selftest_ippsMLDSA_KeyGen_get_size_data_buff(&dataBuffSize);
        if (test_result != IPPCP_ALGO_SELFTEST_OK) {
            return test_result;
        }
        pDataBuff = malloc((size_t)dataBuffSize);
        if (pDataBuff == NULL) {
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        test_result = fips_selftest_ippsMLDSA_KeyGen_get_size(&scratchBuffSize, pDataBuff);
        if (test_result != IPPCP_ALGO_SELFTEST_OK) {
            MEMORY_FREE(pDataBuff, internalMemMgm)
            return test_result;
        }
        pBuffer = malloc((size_t)scratchBuffSize);
        if (pBuffer == NULL) {
            MEMORY_FREE(pDataBuff, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
    }
#else
    IPP_BADARG_RET((NULL == pBuffer) || (NULL == pDataBuff), IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR);
#endif

    /* Test all parameter sets */
    int num_vectors = sizeof(keygen_kat_vectors) / sizeof(keygen_kat_vectors[0]);
    for (int vector_idx = 0; vector_idx < num_vectors; vector_idx++) {
        const MLDSAKeyGenKAT* kat = &keygen_kat_vectors[vector_idx];

        /* Navigate KeyGen buffer layout: [State] → [PublicKey] → [PrivateKey] */
        Ipp8u* pLocDataBuff    = (IPP_ALIGNED_PTR(pDataBuff, IPPCP_MLDSA_ALIGNMENT));
        IppsMLDSAState* pState = (IppsMLDSAState*)pLocDataBuff;

        /* Get current parameter set info for buffer navigation */
        IppsMLDSAInfo info;
        sts = ippsMLDSA_GetInfo(&info, kat->paramSet);
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        /* Skip state, navigate to key buffers */
        int stateSize = 0;
        sts           = ippsMLDSA_GetSize(&stateSize);
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }
        pLocDataBuff += stateSize;

        pLocDataBuff      = (IPP_ALIGNED_PTR(pLocDataBuff, IPPCP_MLDSA_ALIGNMENT));
        Ipp8u* pPublicKey = pLocDataBuff;
        pLocDataBuff += info.publicKeySize;

        pLocDataBuff       = (IPP_ALIGNED_PTR(pLocDataBuff, IPPCP_MLDSA_ALIGNMENT));
        Ipp8u* pPrivateKey = pLocDataBuff;

        /* Initialize state for this parameter set */
        sts = ippsMLDSA_Init(pState, 1, kat->paramSet); // Use minimal message length
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        /* Get scratch buffer */
        Ipp8u* pScratchBuffer = (IPP_ALIGNED_PTR(pBuffer, IPPCP_MLDSA_ALIGNMENT));

        /* Generate keys using fixed seed */
        sts = ippsMLDSA_KeyGen(pPublicKey,
                               pPrivateKey,
                               pState,
                               pScratchBuffer,
                               mldsa_kat_seed_supplier,
                               (void*)kat->seed);
        if (sts != ippStsNoErr) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_BAD_ARGS_ERR;
        }

        /* Compare generated keys with expected KAT values */
        int sk_match = ippcp_is_mem_eq(kat->expected_sk, kat->sk_len, pPrivateKey, kat->sk_len);
        if (sk_match != 1) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_KAT_ERR;
        }

        int pk_match = ippcp_is_mem_eq(kat->expected_pk, kat->pk_len, pPublicKey, kat->pk_len);
        if (pk_match != 1) {
            MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
            return IPPCP_ALGO_SELFTEST_KAT_ERR;
        }
    }

    MEMORY_FREE_2(pDataBuff, pBuffer, internalMemMgm)
    return test_result;
}

#endif // _IPP_DATA
#endif // IPPCP_FIPS_MODE
