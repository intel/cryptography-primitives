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
#include "stateful_sig/lms_internal/lmots.h"
#include "stateful_sig/common.h"

/*
 * Does the randomized hashing for OTS (H function in the Spec)
 * I_q size: I_q_len + val1Len + val2Len + msgLen
 *
 * Input parameters:
 *    I_q         merged buffer consisting of I and the q value
 *    I_q_len     size of I_q
 *    val1        1st value passing to the function
 *    val1Len     size of val1
 *    val2        2nd value passing to the function
 *    val2Len     size of val2
 *    pMsg        pointer to message
 *    msgLen      size of pMsg
 *    hash_method Crypto library hash method
 *
 * Output parameters:
 *    out         resulted n-byte array that contains hash
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_lms_H, (Ipp8u* I_q, const Ipp32s I_q_len,
                   Ipp32u val1, const Ipp32s val1Len,
                   Ipp8u* val2, const Ipp32s val2Len,
                   const Ipp8u* pMsg, const Ipp32s msgLen,
                   Ipp8u* out, const IppsHashMethod* hash_method))
/* clang-format on */
{
    int total_size = I_q_len;

    cp_to_byte(I_q + total_size, val1Len, val1);
    total_size += val1Len;

    CopyBlock(val2, I_q + total_size, val2Len);
    total_size += val2Len;

    if (msgLen > 0) {
        CopyBlock(pMsg, I_q + total_size, msgLen);
        total_size += msgLen;
    }

    return ippsHashMessage_rmf(I_q, total_size, out, hash_method);
}

/*
 * Generates OTS public key
 *
 * Input parameters:
 *    secret_seed random seed to generate secret key
 *    I          pointer to I buffer (I from the spec)
 *    q          q value from the spec
 *    temp_buf   temporary memory (size is CP_PK_I_BYTESIZE + 4 + 2 + 1 + n + n * p bytes at least)
 *    params     OTS parameters
 *
 * Output parameters:
 *    out         resulted n-byte array that contains OTS public key
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_lms_OTS_genPK, (
            Ipp8u* secret_seed, Ipp8u* pI, Ipp32u q,
            Ipp8u* out, Ipp8u* temp_buf, const cpLMOTSParams* params))
/* clang-format on */
{
    IppStatus retCode   = ippStsNoErr;
    const Ipp32s nParam = (Ipp32s)params->n;
    const Ipp32u wParam = params->w;
    const Ipp32u pParam = params->p;
    const Ipp32u two_w  = (1 << wParam);
    Ipp8u D_PRIV_       = D_PRIV;

    Ipp8u* I_q = temp_buf;
    CopyBlock(pI, I_q, CP_PK_I_BYTESIZE);
    cp_to_byte(I_q + CP_PK_I_BYTESIZE, /*q byteLen*/ 4, q);

    Ipp8u* sk_begin = (I_q + CP_PK_I_BYTESIZE + 4 + 2 + 1 + nParam);
    Ipp8u* sk       = sk_begin; // size = n * p
    for (Ipp32u i = 0; i < pParam; i++) {
        // generate secret key from secret seed
        // x_q[i] = cp_lms_H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)
        retCode = cp_lms_H(I_q,
                           CP_PK_I_BYTESIZE + /*q byteLen*/ 4,
                           i,
                           /*i byteLen*/ 2,
                           &D_PRIV_,
                           /*D_PRIV byteLen*/ 1,
                           secret_seed,
                           nParam,
                           sk,
                           params->hash_method);
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

        // chaining
        for (Ipp8u j = 0; j < two_w - 1; j++) {
            // sk = cp_lms_H(I || u32str(q) || u16str(i) || u8str(j) || sk)
            retCode = cp_lms_H(I_q,
                               CP_PK_I_BYTESIZE + /*q byteLen*/ 4,
                               i,
                               /*i byteLen*/ 2,
                               &j,
                               /*j byteLen*/ 1,
                               sk,
                               nParam,
                               sk,
                               params->hash_method);
            IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
        }
        sk += nParam;
    }
    // public_key = cp_lms_H(I || u32str(q) || u16str(D_PBLC) || sk)
    retCode = cp_lms_H(I_q,
                       CP_PK_I_BYTESIZE + /*q byteLen*/ 4,
                       D_PBLC,
                       /*D_PBLC byteLen*/ 2,
                       sk_begin,
                       nParam * (Ipp32s)pParam,
                       NULL,
                       0,
                       out,
                       params->hash_method);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

    return retCode;
}

/*
 * Generates OTS signature
 *
 * Input parameters:
 *    pMsg        pointer to message
 *    msgLen      size of pMsg
 *    secret_seed random seed to generate secret key
 *    pI          pointer to I buffer (I from the spec)
 *    q           q value from the spec
 *    pC          pointer to C buffer (C from the spec)
 *    temp_buf    temporary memory (size is CP_PK_I_BYTESIZE + 4 + 2 + n + max(msgLen, 1 + n) bytes at least)
 *    params      OTS parameters
 *
 * Output parameters:
 *    pY          pointer to Y buffer (Y from the spec)
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_lms_OTS_sign, (
                    const Ipp8u* pMsg, const Ipp32s msgLen,
                    Ipp8u* secret_seed, Ipp8u* pI, Ipp32u q, Ipp8u* pC,
                    Ipp8u* pY,
                    Ipp8u* temp_buf, const cpLMOTSParams* params))
/* clang-format on */
{
    IppStatus retCode   = ippStsNoErr;
    const Ipp32s nParam = (Ipp32s)params->n;
    const Ipp32u wParam = params->w;
    const Ipp32u pParam = params->p;
    Ipp8u D_PRIV_       = D_PRIV;

    Ipp8u Q[CP_LMS_MAX_HASH_BYTESIZE + CP_CKSM_BYTESIZE];
    Ipp8u* I_q = temp_buf;
    // Q = cp_lms_H(I || u32str(q) || u16str(D_MESG) || pC || pMsg)
    // I_q size: CP_PK_I_BYTESIZE + 4 + 2 + nParam + msgLen
    CopyBlock(pI, I_q, CP_PK_I_BYTESIZE);
    cp_to_byte(I_q + CP_PK_I_BYTESIZE, /*q byteLen*/ 4, q);
    retCode = cp_lms_H(I_q,
                       CP_PK_I_BYTESIZE + /*q byteLen*/ 4,
                       D_MESG,
                       /*D_MESG byteLen*/ 2,
                       pC,
                       nParam,
                       pMsg,
                       msgLen,
                       Q,
                       params->hash_method);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

    /* Calculate checksum Cksm(Q) and append it to Q */
    Ipp32u cksmQ = cpCksm(Q, *params);
    // Q || Cksm(Q)
    cp_to_byte(Q + nParam, /*cksmQ byteLen*/ 2, cksmQ);

    Ipp8u* sk = (temp_buf + CP_PK_I_BYTESIZE + 4 + 2 + 1 + nParam);
    for (Ipp32u i = 0; i < pParam; i++) {
        // generate secret key from secret seed
        // x_q[i] = cp_lms_H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)
        retCode = cp_lms_H(I_q,
                           CP_PK_I_BYTESIZE + /*q byteLen*/ 4,
                           i,
                           /*i byteLen*/ 2,
                           &D_PRIV_,
                           /*D_PRIV byteLen*/ 1,
                           secret_seed,
                           nParam,
                           sk,
                           params->hash_method);
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

        // a = coef(Q || Cksm(Q), i, w)
        const Ipp32u a = cpCoef(Q, i, wParam);

        // chaining
        for (Ipp8u j = 0; j < a; j++) {
            // sk = cp_lms_H(I || u32str(q) || u16str(i) || u8str(j) || sk)
            retCode = cp_lms_H(I_q,
                               CP_PK_I_BYTESIZE + /*q byteLen*/ 4,
                               i,
                               /*i byteLen*/ 2,
                               &j,
                               /*j byteLen*/ 1,
                               sk,
                               nParam,
                               sk,
                               params->hash_method);
            IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
        }
        CopyBlock(sk, pY + i * (Ipp32u)nParam, nParam);
    }
    return retCode;
}
