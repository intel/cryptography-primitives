/*************************************************************************
* Copyright (C) 2022 Intel Corporation
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

#ifndef SM4_GCM_H
#define SM4_GCM_H

#include <crypto_mb/sm4.h>

#include <immintrin.h>

#define SM4_GCM_CONTEXT_BUFFER_SLOT_TYPE int64u

#define SM4_GCM_CONTEXT_BUFFER_SLOT_SIZE_BYTES (sizeof(SM4_GCM_CONTEXT_BUFFER_SLOT_TYPE))
#define SM4_GCM_CONTEXT_BUFFER_SIZE_BYTES \
    ((SM4_LINES * SM4_BLOCK_SIZE) / SM4_GCM_CONTEXT_BUFFER_SLOT_SIZE_BYTES)

#define SM4_GCM_HASHKEY_PWR_NUM 8

/*
// Enum to control call sequence
//
// Valid call sequence:
//
// 1) mbx_sm4_gcm_init_mb16
// 2) mbx_sm4_gcm_update_iv_mb16 –  optional, can be called as many times as necessary
// 3) mbx_sm4_gcm_update_aad_mb16 –  optional, can be called as many times as necessary
// 4) mbx_sm4_gcm_encrypt_mb16/mbx_sm4_gcm_decrypt_mb16 –  optional, can be called as many times as necessary
// 5) mbx_sm4_gcm_get_tag_mb16
//
// Call sequence restrictions:
//
// * mbx_sm4_gcm_get_tag_mb16 can be called after IV is fully processed.
//   IV is fully processed if buffer with partial block (Block of less than 16 bytes size) was processed or if mbx_sm4_gcm_update_aad_mb16 was called
// * functions at steps 2-4 can be called as many times as needed to process payload while this functions processes buffers
//   with full blocks (Blocks of 16 bytes size) or empty buffers and length of processed payload is not overflowed.
// * if functions at steps 2-4 called to process a partial block, it can’t be called again.
// * if mbx_sm4_gcm_update_aad_mb16 was called, mbx_sm4_gcm_update_iv_mb16 can’t be called.
// * if mbx_sm4_gcm_encrypt_mb16 or mbx_sm4_gcm_decrypt_mb16 was called, mbx_sm4_gcm_update_aad_mb16 and mbx_sm4_gcm_update_iv_mb16 can’t be called.
// * if mbx_sm4_gcm_encrypt_mb16 was called, mbx_sm4_gcm_decrypt_mb16 can’t be called.
// * if mbx_sm4_gcm_decrypt_mb16 was called, mbx_sm4_gcm_encrypt_mb16 can’t be called.
*/
typedef enum {
    sm4_gcm_update_iv = 0xF0A1,
    sm4_gcm_update_aad,
    sm4_gcm_start_encdec,
    sm4_gcm_enc,
    sm4_gcm_dec,
    sm4_gcm_get_tag
} sm4_gcm_state;

struct _sm4_gcm_context_mb16 {
    /* Set of hashkeys for ghash computation              */
    __m128i hashkey[SM4_GCM_HASHKEY_PWR_NUM][SM4_LINES];
    __m128i j0[SM4_LINES];    /* J0 value accumulator for IV processing             */
    __m128i ghash[SM4_LINES]; /* ghash value accumulator for AAD and TXT processing */
    __m128i ctr[SM4_LINES];   /* counter for gctr encryption                        */

    /*
    // buffer to store IV, AAD and TXT length in bytes
    //
    // this buffer is used to store IV length to compute J0 block
    // and reused to store AAD and TXT length to compute ghash
    //
    // length is stored as follow:
    //
    // J0 computation:
    // [64 bits with IV len (buffer 0)]
    // [64 bits with IV len (buffer 1)]
    // ..
    // [64 bits with IV len (buffer SM4_LINES-1)]
    //
    // Only half of buffer is used for J0 computation
    //
    // ghash computation:
    // [64 bits with AAD len (buffer 0)][64 bits with TXT len (buffer 0)]
    // [64 bits with AAD len (buffer 1)][64 bits with TXT len (buffer 1)]
    // ..
    // [64 bits with AAD len (buffer SM4_LINES-1)][64 bits with TXT len (buffer SM4_LINES-1)]
    //
    */
    int64u len[SM4_LINES * 2];

    mbx_sm4_key_schedule key_sched; /* SM4 key schedule     */
    sm4_gcm_state state;            /* call sequence state  */
};

typedef struct _sm4_gcm_context_mb16 SM4_GCM_CTX_mb16;

MBXAPI(mbx_status16,
       mbx_sm4_gcm_init_mb16,
       (const sm4_key* const pa_key[SM4_LINES],
        const int8u* const pa_iv[SM4_LINES],
        const int iv_len[SM4_LINES],
        SM4_GCM_CTX_mb16* p_context))

MBXAPI(mbx_status16,
       mbx_sm4_gcm_update_iv_mb16,
       (const int8u* const pa_iv[SM4_LINES],
        const int iv_len[SM4_LINES],
        SM4_GCM_CTX_mb16* p_state))
MBXAPI(mbx_status16,
       mbx_sm4_gcm_update_aad_mb16,
       (const int8u* const pa_aad[SM4_LINES],
        const int aad_len[SM4_LINES],
        SM4_GCM_CTX_mb16* p_state))

MBXAPI(mbx_status16,
       mbx_sm4_gcm_encrypt_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* const pa_in[SM4_LINES],
        const int in_len[SM4_LINES],
        SM4_GCM_CTX_mb16* p_context))
MBXAPI(mbx_status16,
       mbx_sm4_gcm_decrypt_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* const pa_in[SM4_LINES],
        const int in_len[SM4_LINES],
        SM4_GCM_CTX_mb16* p_context))

MBXAPI(mbx_status16,
       mbx_sm4_gcm_get_tag_mb16,
       (int8u * pa_tag[SM4_LINES], const int tag_len[SM4_LINES], SM4_GCM_CTX_mb16* p_context))

#endif /* SM4_GCM_H */
