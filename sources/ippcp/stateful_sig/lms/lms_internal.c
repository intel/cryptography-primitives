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
#include "stateful_sig/lms_internal/lms.h"
#include "stateful_sig/common.h"

/*
 * Does the randomized hashing for the tree out of OTS (H function in LMS Spec)
 * I size: 16 + 4 + val2Len + val3Len + msgLen
 *
 * Input parameters:
 *    I           pointer to I buffer (I from the spec)
 *    val1        1st value passing to the function
 *    val1Len     size of val1
 *    val2        2nd value passing to the function
 *    val2Len     size of val2
 *    val3        3rd value passing to the function
 *    val3Len     size of val3
 *    pMsg        pointer to message
 *    msgLen      size of pMsg
 *    hash_method Crypto library hash method
 *
 * Output parameters:
 *    out         resulted n-byte array that contains hash
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_lms_H_tree, (
                   Ipp8u* I,
                   Ipp32u val1,
                   Ipp32u val2, const Ipp32s val2Len,
                   Ipp8u* val3, const Ipp32s val3Len,
                   Ipp8u* pMsg, const Ipp32s msgLen,
                   Ipp8u* out, const IppsHashMethod* hash_method))
/* clang-format on */
{
    int total_size = CP_PK_I_BYTESIZE;

    cp_to_byte(I + total_size, /*val1 byteLen*/ 4, val1);
    total_size += 4;

    cp_to_byte(I + total_size, val2Len, val2);
    total_size += val2Len;

    CopyBlock(val3, I + total_size, val3Len);
    total_size += val3Len;

    if (msgLen > 0) {
        CopyBlock(pMsg, I + total_size, msgLen);
        total_size += msgLen;
    }

    return ippsHashMessage_rmf(I, total_size, out, hash_method);
}

/*
 * Builds the LMS tree. The function calls from keygen or sign functions
 * The algorithm use auxiliary memory to store nodes of the built tree.
 * It significantly reduces calculations on the sign stage and significantly
 * improves the performance by storing already calculated tree nodes.
 *
 * Input parameters:
 *    isKeyGen      parameter == 1 if the function is called from keygen function.
 *                  Otherwise it equals to 0
 *    secret_seed   random seed to generate secret key
 *    pI            pointer to I buffer (I from the spec)
 *    idx_leaf      index of leaf for which the authentication path is built.
 *                  In case of calling from keygen function parameter is ignored
 *    temp_buf      temporary memory (size is (((((CP_PK_I_BYTESIZE + 4 + 2 + n + n) + h + 1) + h * n) + n * p) + n) + (CP_PK_I_BYTESIZE + 4 + 2 + 1 + n + n * p) bytes at least)
 *    pAuxiliaryMem auxiliary memory to store nodes of the tree.
 *                  If isKeyGen == 1, nodes are written to pAuxiliaryMem
 *                  If isKeyGen == 0, nodes are read from pAuxiliaryMem
 *    aux_size      size of pAuxiliaryMem (bytes)
 *    lmsParams     LMS parameters
 *    lmotsParams   OTS parameters
 *
 * Output parameters:
 *    out         resulted n-byte array that contains the public key
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_lms_tree_hash, (Ipp8u isKeyGen,
                                           Ipp8u* pSecretSeed,
                                           Ipp8u* pI,
                                           Ipp8u* out,
                                           Ipp32u idx_leaf,
                                           Ipp8u* temp_buf,
                                           Ipp8u* pAuxiliaryMem,
                                           Ipp32s aux_size,
                                           const cpLMSParams* lmsParams,
                                           const cpLMOTSParams* lmotsParams))
/* clang-format on */
{
    IppStatus retCode = ippStsErr;
    const Ipp32u n    = lmotsParams->n;
    const Ipp32s n_s  = (Ipp32s)n;
    const Ipp32u h    = lmsParams->h;

    Ipp8u* I_r = temp_buf;
    CopyBlock(pI, I_r, CP_PK_I_BYTESIZE);

    Ipp8u* heights = I_r + (CP_PK_I_BYTESIZE + 4 + 2 + n_s + n_s); // size: h
    Ipp8u* stack   = heights + (h + 1);

    Ipp32s stack_size = 0;
    Ipp8u *node, *temp_node;
    // Note: there is no overflow since the maximum value for h is 25 according to the Spec
    for (Ipp32u i = 0; i < (Ipp32u)(1 << h); i++) {
        Ipp8u b;
        if ((isKeyGen == 0) && (aux_size > 0) && (idx_leaf != i)) {
            b                = 0;
            Ipp32u h_local   = 0;
            Ipp32u j_local   = i;
            Ipp32u idx_local = idx_leaf;
            while (!b || h_local < h - 1) {
                if ((idx_local ^ 1) == j_local) {
                    Ipp32u aux_idx = ((1 << (h - h_local)) - 2) + j_local;
                    if (aux_idx * n < (Ipp32u)aux_size - n) {
                        b = 1;
                    }
                    break;
                }
                h_local++;
                j_local >>= 1;
                idx_local >>= 1;
            }
            if (b) {
                continue;
            }
        }

        Ipp32u r = (1 << h) + i;  // r = 2^h + i
        node     = stack + h * n; // size: n
        // 2*2^0 + 2*2^1 + 2*2^2 +... + 2*2^(h-1) = 2 * ((1 << h) - 1)
        Ipp32u aux_idx = ((1 << h) - 2) + i;

        if ((isKeyGen == 0) && (aux_idx * n < (Ipp32u)aux_size - n)) {
            CopyBlock(pAuxiliaryMem + aux_idx * n, node, n_s);
        } else {
            temp_node = node + n_s;
            // public key generation
            retCode = cp_lms_OTS_genPK(
                pSecretSeed,
                pI,
                i,
                node,
                temp_node,
                lmotsParams); // temp_node size: CP_PK_I_BYTESIZE + 4 + 2 + 1 + n + n * p
            IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
            // hash public key in leaf node
            retCode = cp_lms_H_tree(I_r,
                                    r,
                                    D_LEAF,
                                    2,
                                    node,
                                    n_s,
                                    NULL,
                                    0,
                                    node,
                                    lmsParams->hash_method); // size: n
            IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
        }

        if (isKeyGen == 0 && (idx_leaf ^ 1) == i) {
            CopyBlock(node, out, n_s);
        }
        if (isKeyGen == 1 && aux_idx * n < (Ipp32u)aux_size - n) {
            CopyBlock(node, pAuxiliaryMem + aux_idx * n, n_s);
        }

        // calculate a root of sub-tree
        heights[stack_size] = 0;
        Ipp32u j            = i;
        while (stack_size > 0 && heights[stack_size - 1] == heights[stack_size]) {
            stack_size--; // stack.pop

            j >>= 1;      // j = j / 2
            r >>= 1;      // r = r / 2

            aux_idx = ((1 << (h - heights[stack_size] - 1)) - 2) + j;
            if (isKeyGen == 0 && aux_idx * n <= (Ipp32u)aux_size - n) {
                CopyBlock(pAuxiliaryMem + aux_idx * n, node, n_s);
            } else {
                retCode = cp_lms_H_tree(I_r,
                                        r,
                                        D_INTR,
                                        2,
                                        stack + (stack_size * n_s),
                                        n_s,  // left
                                        node,
                                        n_s,  // right
                                        node, // out
                                        lmsParams->hash_method);
                IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
            }
            if (isKeyGen == 1 && aux_idx * n <= (Ipp32u)aux_size - n) {
                CopyBlock(node, pAuxiliaryMem + aux_idx * n, n_s);
            }

            heights[stack_size]++;

            if (isKeyGen == 0 && ((idx_leaf >> heights[stack_size]) ^ 1) == j) {
                CopyBlock(node, out + (heights[stack_size]) * n_s, n_s);
            }
        }
        CopyBlock(node, stack + (stack_size * n_s), n_s);
        stack_size++; // stack.push
    }

    // fill the output
    if (isKeyGen == 1) {
        CopyBlock(stack, out, n_s);
    } else if (aux_size > 0) {
        for (Ipp32u h_local = 0; h_local < h; h_local++) {
            Ipp32u j_local = (idx_leaf >> h_local) ^ 1;
            Ipp32u aux_idx = ((1 << (h - h_local)) - 2) + j_local;
            if (aux_idx * n < (Ipp32u)aux_size - n) {
                CopyBlock(pAuxiliaryMem + (aux_idx * n), out + (h_local * n), n_s);
            }
        }
    }

    return retCode;
}
