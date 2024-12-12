/*************************************************************************
* Copyright (C) 2020 Intel Corporation
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

#if !defined(_SM3_MB16_H)
#define _SM3_MB16_H

#include <internal/sm3/sm3_common.h>

#include <crypto_mb/status.h>
#include <crypto_mb/defs.h>
#include <crypto_mb/sm3.h>

#if (_MBX >= _MBX_K1)

/*
// change endian
*/
static __ALIGN64 const int8u swapBytesCtx[] = { 3,  2,  1,  0,  7,  6,  5,  4,  11, 10, 9,  8,  15,
                                                14, 13, 12, 3,  2,  1,  0,  7,  6,  5,  4,  11, 10,
                                                9,  8,  15, 14, 13, 12, 3,  2,  1,  0,  7,  6,  5,
                                                4,  11, 10, 9,  8,  15, 14, 13, 12, 3,  2,  1,  0,
                                                7,  6,  5,  4,  11, 10, 9,  8,  15, 14, 13, 12 };

#define SIMD_ENDIANNESS32(x) _mm512_shuffle_epi8((x), _mm512_loadu_si512(swapBytesCtx));

/*
// internal functions
*/

#define sm3_avx512_mb16 OWNAPI(sm3_avx512_mb16)
void sm3_avx512_mb16(int32u hash_pa[][16], const int8u* const msg_pa[16], int len[16]);

mbx_status16 internal_avx512_sm3_mask_init_mb16(SM3_CTX_mb16* p_state, unsigned short mb_mask);
mbx_status16 internal_avx512_sm3_final_mb16(int8u* hash_pa[16], SM3_CTX_mb16* p_state);
mbx_status16 internal_avx512_sm3_msg_digest_mb16(const int8u* const msg_pa[16],
                                                 int len[16],
                                                 int8u* hash_pa[16]);
mbx_status16 internal_avx512_sm3_update_mb16(const int8u* const msg_pa[16],
                                             int len[16],
                                             SM3_CTX_mb16* p_state);


#endif /* #if (_MBX>=_MBX_K1) */

#endif /* _SM3_MB16_H */
