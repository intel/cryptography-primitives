/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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

#include "owndefs.h"
#include "xmss_internal/xmss.h"

/*
 * Does the randomized hashing in the tree
 *
 * Input parameters:
 *    left        left  half of the hash function input (n-byte array)
 *    right       right half of the hash function input (n-byte array)
 *    seed        key for the prf function (n-byte array)
 *    adrs        address ADRS of the hash function call
 *    temp_buf    temporary memory (size is 6 * n bytes at least)
 *    params      WOTS parameters (w, log2_w, n, len, len_1, hash_method)
 *
 * Output parameters:
 *    out         resulted n-byte array that contains hash
 */

IPP_OWN_DEFN(IppStatus, cp_xmss_rand_hash, (Ipp8u* left, Ipp8u* right, Ipp8u* seed,
            Ipp8u* adrs, Ipp8u* out, Ipp8u* temp_buf, const cpWOTSParams* params)){
    IppStatus retCode = ippStsNoErr;
    Ipp8u* pMsg = temp_buf;
    Ipp8u* pKey = temp_buf + 2 * params->n;
    Ipp8u* temp = temp_buf + 3 * params->n;

    cp_xmss_set_key_and_mask(adrs, /*key bitmask*/ 0);
    retCode = cp_xmss_prf(seed, adrs, pKey, temp, params);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

    cp_xmss_set_key_and_mask(adrs, /*left bitmask*/ 1);
    retCode = cp_xmss_prf(seed, adrs, pMsg, temp, params);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

    cp_xmss_set_key_and_mask(adrs, /*right bitmask*/ 2);
    retCode = cp_xmss_prf(seed, adrs, pMsg + params->n, temp, params);
    IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

    // null adrs
    cp_xmss_set_key_and_mask(adrs, 0);

    // (LEFT XOR BM_0) || (RIGHT XOR BM_1)
    for (Ipp32s i = 0; i < params->n; ++i) {
        pMsg[i]             = left[i]  ^ pMsg[i];
        pMsg[i + params->n] = right[i] ^ pMsg[i + params->n];
    }

    //H(KEY, pMsg);
    retCode = cp_do_xmss_hash(/*H padding id*/ 1, pKey, pMsg, 2 * params->n, out, temp, params);
    return retCode;
}

/*
 * Compute the leaves of the binary hash tree, a so-called L-tree.
 * An L-tree is an unbalanced binary hash tree, distinct but
 * similar to the main XMSS binary hash tree. The function takes as input a
 * WOTS+ public key pk and compresses it to a single n-byte value pk[0].
 * It also takes as input an L-tree address adrs that encodes the address
 * of the L-tree and seed
 *
 * temp_buf size is 6 * n bytes at least.
 *
 */

IPP_OWN_DEFN(IppStatus, cp_xmss_ltree, (Ipp8u* pk, Ipp8u* seed, Ipp8u* adrs, Ipp8u* temp_buf, const cpWOTSParams* params)) {
    IppStatus retCode = ippStsNoErr;
    Ipp32s len_ = params->len;
    Ipp32s n_ = params->n;

    // tree height is 0 for now
    cp_xmss_set_tree_height(adrs, 0);

    while (len_ > 1) {
        for (Ipp32s i = 0; i < len_ / 2; i++) {
            cp_xmss_set_tree_index_8(adrs, (Ipp8u) i);

            retCode = cp_xmss_rand_hash(pk + (2 * i * n_), pk + ((2 * i * n_) + n_), seed, adrs, pk + (i * n_), temp_buf, params);
            IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
        }
        if ((len_ & 1) == 1) {
            CopyBlock(pk + (n_ * (len_ - 1)), pk + (n_ * (len_ / 2)), n_);
            len_ = (len_ >> 1) + 1;
        }
        else {
            len_ = len_ >> 1;
        }
        // increase the tree height
        cp_xmss_set_tree_height(adrs, cp_xmss_get_tree_height(adrs) + 1);
    }

    // null tree height and tree index
    cp_xmss_set_tree_height(adrs, 0);
    cp_xmss_set_tree_index_8(adrs, (Ipp8u) 0);
    return retCode;
}

/*
 * Builds the binary hash tree, a so-called L-tree.
 * For the height of a node within a tree, counting starts with the leaves at height zero.
 * The treeHash algorithm returns the root node of a tree (out).
 * The treeHash algorithm described here uses a stack holding up to (h - 1) nodes.
 * We furthermore assume that the height of a node is stored alongside
 * a node’s value (an n-byte string) on the stack.
 *
 * temp_buf size is (h + 1) * (n + 1) + 2 * len * n + 7 * n + 32 bytes at least.
 *
 */
IPP_OWN_DEFN(IppStatus, cp_xmss_tree_hash, (Ipp8u isKeyGen, IppsXMSSPrivateKeyState* pSecretKey, Ipp8u* adrs,
                Ipp8u* out, Ipp32u idx_leaf, Ipp8u* temp_buf,
                Ipp32s h, const cpWOTSParams* params)){
    IppStatus retCode = ippStsNoErr;
    Ipp8u* heights = temp_buf;
    Ipp8u* stack = heights + (h + 1);

    Ipp32s len = params->len;
    Ipp32s n = params->n;
    Ipp32s len_n = len * n;
    Ipp32s stack_size = 0;
    Ipp8u *node, *temp_node;
    // Note: there is no overflow since the maximum value for h is 20 according to the Spec
    for(Ipp32u i = 0; i < (Ipp32u)(1 << h); ++i) {
        // generate OTS public key
        cp_to_byte(adrs, ADRS_SIZE, 0);
        cp_xmss_set_tree_type(adrs, /*OTS hash*/ 0);
        cp_xmss_set_ots_address(adrs, i);
        node = stack + (h + 1) * n; // size: len * n
        temp_node = node + len_n;
        retCode = cp_xmss_WOTS_genPK(pSecretKey->pSecretSeed, node, pSecretKey->pPublicSeed, adrs, temp_node, params); // size: 7 * n + 32
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

        // call ltree
        cp_to_byte(adrs, ADRS_SIZE, 0);
        cp_xmss_set_tree_type(adrs, /*L-tree*/ 1);
        cp_xmss_set_ltree_address(adrs, i);
        retCode = cp_xmss_ltree(node, pSecretKey->pPublicSeed, adrs, temp_node, params); // size: 7 * n
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

        if (isKeyGen == 0 && (idx_leaf ^ 1) == i) {
            CopyBlock(node, out, n);
        }

        // calculate a root of sub-tree
        cp_to_byte(adrs, ADRS_SIZE, 0);
        cp_xmss_set_tree_type(adrs, /*hash tree*/ 2);
        cp_xmss_set_tree_height(adrs, 0);
        cp_xmss_set_tree_index_32(adrs, i);
        heights[stack_size] = 0;
        while(stack_size > 0 && heights[stack_size - 1] == heights[stack_size]) {
            Ipp32u idx = cp_xmss_get_tree_index(adrs);
            idx = (idx - 1) / 2;
            cp_xmss_set_tree_index_32(adrs, idx);
            stack_size--; // stack.pop

            retCode = cp_xmss_rand_hash(stack + (stack_size * n), node, pSecretKey->pPublicSeed, adrs, node, temp_node, params);
            IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

            heights[stack_size]++;
            cp_xmss_set_tree_height(adrs, heights[stack_size]);

            if (isKeyGen == 0 && ((idx_leaf >> heights[stack_size]) ^ 1) == idx) {
                CopyBlock(node, out + heights[stack_size] * n, n);
            }
        }
        CopyBlock(node, stack + (stack_size * n), n);
        stack_size++; // stack.push
    }
    if(isKeyGen == 1) {
        CopyBlock(stack, out, n);
    }

    return retCode;
}
