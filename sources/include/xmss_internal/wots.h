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

#ifndef IPPCP_WOTS_H_
#define IPPCP_WOTS_H_

#include "owndefs.h"
#include "pcptool.h"

#include "stateful_sig_common/common.h"

// WOTS+ algorithms params. See 3.1.1. XMSS spec.
typedef struct {
    Ipp32s n;
    Ipp32u w;
    Ipp32s len_1;
    Ipp32s len;
    Ipp32s log2_w;
    IppsHashMethod* hash_method;
} cpWOTSParams;

// declarations
#define cp_xmss_base_w OWNAPI(cp_xmss_base_w)
/* clang-format off */
IPP_OWN_DECL(void, cp_xmss_base_w, (const Ipp8u* pMsg,
                                    Ipp32s out_len,
                                    Ipp8u* basew,
                                    cpWOTSParams* params))
/* clang-format on */

#define cp_do_xmss_hash OWNAPI(cp_do_xmss_hash)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_do_xmss_hash, (Ipp32u padding_id,
                                          const Ipp8u* key,
                                          const Ipp8u* msg,
                                          Ipp32s msgLen,
                                          Ipp8u* out,
                                          Ipp8u* temp_buf,
                                          const cpWOTSParams* params))
/* clang-format on */

#define cp_xmss_prf OWNAPI(cp_xmss_prf)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_xmss_prf, (const Ipp8u* key,
                                      const Ipp8u* index,
                                      Ipp8u* out,
                                      Ipp8u* temp_buf,
                                      const cpWOTSParams* params))
/* clang-format on */


#define cp_xmss_prf_keygen OWNAPI(cp_xmss_prf_keygen)
IPP_OWN_DECL(IppStatus,
             cp_xmss_prf_keygen,
             (const Ipp8u* key,
              const Ipp8u* msg,
              Ipp32s msgLen,
              Ipp8u* out,
              Ipp8u* temp_buf,
              const cpWOTSParams* params))

#define cp_xmss_chain OWNAPI(cp_xmss_chain)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_xmss_chain, (Ipp8u* X,
                                        Ipp8u i,
                                        Ipp8u s,
                                        Ipp8u* pSeed,
                                        Ipp8u* adrs,
                                        Ipp8u* out,
                                        Ipp8u* temp_buf,
                                        const cpWOTSParams* params))
/* clang-format on */

#define cp_xmss_WOTS_pkFromSig OWNAPI(cp_xmss_WOTS_pkFromSig)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_xmss_WOTS_pkFromSig, (const Ipp8u* M,
                                                 Ipp8u* sig,
                                                 Ipp8u* pSeed,
                                                 Ipp8u* adrs,
                                                 Ipp8u* out,
                                                 Ipp8u* temp_buf,
                                                 cpWOTSParams* params))
/* clang-format on */

#define cp_xmss_rand_num OWNAPI(cp_xmss_rand_num)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_xmss_rand_num, (Ipp8u* out,
                                           Ipp32s byteSize,
                                           IppBitSupplier rndFunc,
                                           void* pRndParam))
/* clang-format on */

#define cp_xmss_WOTS_genSK OWNAPI(cp_xmss_WOTS_genSK)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_xmss_WOTS_genSK, (Ipp8u* pSecretSeed,
                                             Ipp8u* pPublicSeed,
                                             Ipp8u* adrs,
                                             Ipp8u* out,
                                             Ipp8u* pubSeed_adrs,
                                             const cpWOTSParams* params))

/* clang-format on */
#define cp_xmss_WOTS_genPK OWNAPI(cp_xmss_WOTS_genPK)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_xmss_WOTS_genPK, (Ipp8u* pSecretSeed,
                                             Ipp8u* pPublicKey,
                                             Ipp8u* pPublicSeed,
                                             Ipp8u* adrs,
                                             Ipp8u* temp_buf,
                                             const cpWOTSParams* params))
/* clang-format on */

#define cp_xmss_WOTS_sign OWNAPI(cp_xmss_WOTS_sign)
/* clang-format off */
IPP_OWN_DECL(IppStatus, cp_xmss_WOTS_sign, (const Ipp8u* M,
                                            Ipp8u* pSecretSeed,
                                            Ipp8u* pSignature,
                                            Ipp8u* pPublicSeed,
                                            Ipp8u* adrs,
                                            Ipp8u* temp_buf,
                                            cpWOTSParams* params))
/* clang-format on */

/*
 * Implement a ceil function that returns the smallest integer greater than or equal to x.
 *
 * Input parameters:
 *    x   double precision floating point value
 */

__IPPCP_INLINE Ipp32s cp_xmss_ceil(double x)
{
    Ipp32s int_val = (Ipp32s)x;
    if (int_val == x || x <= 0.0) {
        return int_val;
    } else {
        return int_val + 1;
    }
}

/*
 * Set idx as a 4-elements byte array to adrs
 *
 * Input parameters:
 *    adrs      array of bytes
 *    idx       value to represent as 4-bytes array
 *    word_id   int32 idx in the adrs array
 * Output parameters:
 *    adrs      changed array of bytes
 */

__IPPCP_INLINE void cp_xmss_set_adrs_idx(Ipp8u* adrs, Ipp32u value, int word_id)
{
    adrs[4 * word_id + 3] = (Ipp8u)value & 0xff;
    adrs[4 * word_id + 2] = (Ipp8u)(value >> 8) & 0xff;
    adrs[4 * word_id + 1] = (Ipp8u)(value >> 16) & 0xff;
    adrs[4 * word_id]     = (Ipp8u)(value >> 24) & 0xff;
}

/*
 * Get idx from a 4-elements byte array
 *
 * Returns:
 *    value to represent as 4-bytes array
 *
 * Input parameters:
 *    input     array of bytes
 *    word_id   int32 idx in the input array
 */

__IPPCP_INLINE Ipp32u cp_xmss_get_adrs_idx(Ipp8u* input, int word_id)
{
    Ipp32u idx = input[4 * word_id];
    idx        = (idx << 8) | input[4 * word_id + 1];
    idx        = (idx << 8) | input[4 * word_id + 2];
    idx        = (idx << 8) | input[4 * word_id + 3];
    return idx;
}

/*
 * Find an index in the adrs array to set 1 byte to
 *
 * Returns:
 *    index of adrs to set data to
 *
 * Input parameters:
 *    word_id   int32 idx in the adrs array
 */

__IPPCP_INLINE Ipp8u cp_xmss_set_adrs_1_byte(int word_id) { return (Ipp8u)(4 * word_id + 3); }

// description of internals for OTS Hash / L-tree / Hash tree address is following
// +-----------------------------------------------------+
// | layer address                              (32 bits)|
// +-----------------------------------------------------+
// | tree address                               (64 bits)|
// +-----------------------------------------------------+
// | type = 0 / 1 / 2                           (32 bits)|
// +-----------------------------------------------------+
// | OTS address / L-tree address / Padding = 0 (32 bits)|
// +-----------------------------------------------------+
// | chain address / tree height                (32 bits)|
// +-----------------------------------------------------+
// | hash address / tree index                  (32 bits)|
// +-----------------------------------------------------+
// | keyAndMask                                 (32 bits)|
// +-----------------------------------------------------+

// 3: tree type
__IPPCP_INLINE void cp_xmss_set_tree_type(Ipp8u* adrs, Ipp8u value)
{
    adrs[cp_xmss_set_adrs_1_byte(3)] = value;
}

// 4: OTS address / L-tree address
__IPPCP_INLINE void cp_xmss_set_ots_address(Ipp8u* adrs, Ipp32u value)
{
    cp_xmss_set_adrs_idx(adrs, value, 4);
}

__IPPCP_INLINE void cp_xmss_set_ltree_address(Ipp8u* adrs, Ipp32u value)
{
    cp_xmss_set_adrs_idx(adrs, value, 4);
}

// 5: chain address / tree height
__IPPCP_INLINE void cp_xmss_set_chain_address(Ipp8u* adrs, Ipp8u value)
{
    adrs[cp_xmss_set_adrs_1_byte(5)] = value;
}

__IPPCP_INLINE void cp_xmss_set_tree_height(Ipp8u* adrs, Ipp8u value)
{
    adrs[cp_xmss_set_adrs_1_byte(5)] = value;
}

__IPPCP_INLINE Ipp8u cp_xmss_get_tree_height(Ipp8u* adrs)
{
    return adrs[cp_xmss_set_adrs_1_byte(5)];
}

// 6: hash address / tree index
__IPPCP_INLINE void cp_xmss_set_hash_address(Ipp8u* adrs, Ipp8u value)
{
    adrs[cp_xmss_set_adrs_1_byte(6)] = value;
}

__IPPCP_INLINE void cp_xmss_set_tree_index_8(Ipp8u* adrs, Ipp8u value)
{
    adrs[cp_xmss_set_adrs_1_byte(6)] = value;
}

__IPPCP_INLINE void cp_xmss_set_tree_index_32(Ipp8u* adrs, Ipp32u value)
{
    cp_xmss_set_adrs_idx(adrs, value, 6);
}

__IPPCP_INLINE Ipp32u cp_xmss_get_tree_index(Ipp8u* input)
{
    return cp_xmss_get_adrs_idx(input, 6);
}

// 7: keyAndMask
__IPPCP_INLINE void cp_xmss_set_key_and_mask(Ipp8u* adrs, Ipp8u value)
{
    adrs[cp_xmss_set_adrs_1_byte(7)] = value;
}

#endif /* #ifndef IPPCP_WOTS_H_ */
