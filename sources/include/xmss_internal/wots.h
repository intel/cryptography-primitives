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
#define base_w OWNAPI(base_w)
IPP_OWN_DECL(void, base_w, (const Ipp8u* pMsg, Ipp32s out_len, Ipp8u* basew, cpWOTSParams* params))

#define do_xmss_hash OWNAPI(do_xmss_hash)
IPP_OWN_DECL(IppStatus, do_xmss_hash, (Ipp32u padding_id, const Ipp8u* key,
                const Ipp8u* msg, Ipp32s msgLen, Ipp8u* out, Ipp8u* temp_buf, cpWOTSParams* params))

#define prf OWNAPI(prf)
IPP_OWN_DECL(IppStatus, prf, (const Ipp8u* key, const Ipp8u* index, Ipp8u* out, Ipp8u* temp_buf, cpWOTSParams* params))

#define chain OWNAPI(chain)
IPP_OWN_DECL(IppStatus, chain, (Ipp8u* X, Ipp8u i, Ipp8u s, Ipp8u* pSeed, Ipp8u* adrs,
            Ipp8u* out, Ipp8u* temp_buf, cpWOTSParams* params))

#define WOTS_pkFromSig OWNAPI(WOTS_pkFromSig)
IPP_OWN_DECL(IppStatus, WOTS_pkFromSig, (const Ipp8u* M, Ipp8u* sig, Ipp8u* pSeed,
            Ipp8u* adrs, Ipp8u* out, Ipp8u* temp_buf, cpWOTSParams* params))

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

__IPPCP_INLINE void set_adrs_idx(Ipp8u* adrs, Ipp32u idx, int word_id){
    adrs[4 * word_id + 3] = (Ipp8u) idx        & 0xff;
    adrs[4 * word_id + 2] = (Ipp8u)(idx >>  8) & 0xff;
    adrs[4 * word_id + 1] = (Ipp8u)(idx >> 16) & 0xff;
    adrs[4 * word_id]     = (Ipp8u)(idx >> 24) & 0xff;
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

__IPPCP_INLINE Ipp8u set_adrs_1_byte(int word_id){
    return (Ipp8u)(4 * word_id + 3);
}

/*
 * Implement a ceil function that returns the smallest integer greater than or equal to x.
 *
 * Input parameters:
 *    x   double precision floating point value
 */

__IPPCP_INLINE Ipp32s cpCeil(double x) {
    Ipp32s int_val = (Ipp32s) x;
    if(int_val == x || x <= 0.0){
        return int_val;
    }
    else{
        return int_val + 1;
    }
}

#endif /* #ifndef IPPCP_WOTS_H_ */

