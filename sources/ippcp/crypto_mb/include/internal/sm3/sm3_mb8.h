/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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

#if !defined(_SM3_MB8_H)
#define _SM3_MB8_H

#include <internal/sm3/sm3_common.h>

#include <crypto_mb/defs.h>
#include <crypto_mb/sm3.h>

#if (_MBX >= _MBX_K1)

/*
// change endian
*/

static __ALIGN64 const int8u swapBytesCtx[] = { 3, 2,  1,  0,  7,  6, 5,  4,  11, 10, 9,
                                                8, 15, 14, 13, 12, 3, 2,  1,  0,  7,  6,
                                                5, 4,  11, 10, 9,  8, 15, 14, 13, 12 };

#define SIMD_ENDIANNESS32(x) _mm256_shuffle_epi8((x), _mm256_loadu_si256((__m256i*)swapBytesCtx));
#define SM3_NUM_BUFFERS8     (8) /*       max number of buffers in sm3 multi-buffer 8       */

/*  sm3 hash value in multi-buffer 8 format  */
typedef int32u sm3_hash_mb8[SM3_SIZE_IN_WORDS][SM3_NUM_BUFFERS8];
struct _sm3_context_mb8 {
    int msg_buff_idx[SM3_NUM_BUFFERS8];                     /*   buffer entry    */
    int64u msg_len[SM3_NUM_BUFFERS8];                       /*  message length   */
    int8u msg_buffer[SM3_NUM_BUFFERS8][SM3_MSG_BLOCK_SIZE]; /*      buffer       */
    __ALIGN64 sm3_hash_mb8 msg_hash;                        /* intermediate hash */
};

typedef struct _sm3_context_mb8 SM3_CTX_mb8;

/*
// internal functions
*/

EXTERN_C mbx_status sm3_init_mb8(SM3_CTX_mb8* p_state);
EXTERN_C mbx_status sm3_update_mb8(const int8u* const msg_pa[8], int len[8], SM3_CTX_mb8* p_state);
EXTERN_C mbx_status sm3_final_mb8(int8u* hash_pa[8], SM3_CTX_mb8* p_state);
EXTERN_C mbx_status sm3_msg_digest_mb8(const int8u* const msg_pa[8], int len[8], int8u* hash_pa[8]);

EXTERN_C void sm3_avx512_mb8(int32u hash_pa[][8], const int8u* const msg_pa[8], int len[8]);
EXTERN_C void sm3_mask_init_mb8(SM3_CTX_mb8* p_state, __mmask8 mb_mask);

#endif /* #if (_MBX>=_MBX_K1) */

#endif /* _SM3_MB8_H */
