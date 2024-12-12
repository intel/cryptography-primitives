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

#ifndef SM4_CCM_H
#define SM4_CCM_H

#include <crypto_mb/sm4.h>

#include <immintrin.h>

#define MIN_CCM_IV_LENGTH  7
#define MAX_CCM_IV_LENGTH  13
#define MIN_CCM_TAG_LENGTH 4
#define MAX_CCM_TAG_LENGTH 16
#define MAX_CCM_AAD_LENGTH 65280 /* 2^16 - 2^8 */

#define SM4_CCM_CONTEXT_BUFFER_SLOT_TYPE int64u

#define SM4_CCM_CONTEXT_BUFFER_SLOT_SIZE_BYTES (sizeof(SM4_CCM_CONTEXT_BUFFER_SLOT_TYPE))
#define SM4_CCM_CONTEXT_BUFFER_SIZE_BYTES \
    ((SM4_LINES * SM4_BLOCK_SIZE) / SM4_CCM_CONTEXT_BUFFER_SLOT_SIZE_BYTES)

/*
// Enum to control call sequence
//
// Valid call sequence:
//
// 1) mbx_sm4_ccm_init_mb16
// 2) mbx_sm4_ccm_update_aad_mb16 –  optional
// 3) mbx_sm4_ccm_encrypt_mb16/mbx_sm4_ccm_decrypt_mb16 –  optional, can be called as many times as necessary
// 4) mbx_sm4_ccm_get_tag_mb16
//
// Call sequence restrictions:
//
// * mbx_sm4_ccm_get_tag_mb16 can be called after mbx_sm4_ccm_init_mb16 has been called.
// * functions at steps 2-3 can be called as many times as needed to process payload while this functions processes buffers
//   with full blocks (Blocks of 16 bytes size) or empty buffers and length of processed payload is not overflowed.
// * if functions at steps 2-3 called to process a partial block, it can’t be called again.
// * if mbx_sm4_ccm_encrypt_mb16 or mbx_sm4_ccm_decrypt_mb16 was called, mbx_sm4_ccm_update_aad_mb16 can’t be called.
// * if mbx_sm4_ccm_encrypt_mb16 was called, mbx_sm4_ccm_decrypt_mb16 can’t be called.
// * if mbx_sm4_ccm_decrypt_mb16 was called, mbx_sm4_ccm_encrypt_mb16 can’t be called.
*/
typedef enum {
    sm4_ccm_update_aad = 0xF0A1,
    sm4_ccm_start_encdec,
    sm4_ccm_enc,
    sm4_ccm_dec,
    sm4_ccm_get_tag
} sm4_ccm_state;

struct _sm4_ccm_context_mb16 {
    int64u msg_len[SM4_LINES]; /* Message length (in bytes) of all lines */
    int64u total_processed_len
        [SM4_LINES]; /* Total processed plaintext/ciphertext length (in bytes) of all lines */
    int tag_len[SM4_LINES];         /* Tag length (in bytes) of all lines */
    int iv_len[SM4_LINES];          /* Total IV length (in bytes) of all lines */
    __m128i ctr0[SM4_LINES];        /* CTR0 content */
    __m128i ctr[SM4_LINES];         /* CTR content */
    __m128i hash[SM4_LINES];        /* hash value accumulator for AAD and TXT processing */

    mbx_sm4_key_schedule key_sched; /* SM4 key schedule     */
    sm4_ccm_state state;            /* call sequence state  */
};

typedef struct _sm4_ccm_context_mb16 SM4_CCM_CTX_mb16;

/*
 * Initializes SM4-CCM context.
 *
 * @param[in] pa_key        Array of key pointers
 * @param[in] pa_iv         Array of IV pointers
 * @param[in] iv_len        Array of IV lengths
 * @param[in] tag_len       Array of authentication tag lengths
 * @param[in] msg_len       Array of total message lengths
 * @param[in/out] p_context SM4-CCM context
 *
 * @return Bitmask of operation status
 */

MBXAPI(mbx_status16,
       mbx_sm4_ccm_init_mb16,
       (const sm4_key* const pa_key[SM4_LINES],
        const int8u* const pa_iv[SM4_LINES],
        const int iv_len[SM4_LINES],
        const int tag_len[SM4_LINES],
        const int64u msg_len[SM4_LINES],
        SM4_CCM_CTX_mb16* p_context))
/*
 * Digests additional authenticated data (AAD) for 16 buffers
 *
 * @param[in] pa_aad        Array of AAD pointers
 * @param[in] aad_len       Array of AAD lengths
 * @param[in/out] p_context SM4-CCM context
 *
 * @return Bitmask of operation status
 */
MBXAPI(mbx_status16,
       mbx_sm4_ccm_update_aad_mb16,
       (const int8u* const pa_aad[SM4_LINES],
        const int aad_len[SM4_LINES],
        SM4_CCM_CTX_mb16* p_context))
/*
 * Retrieves authentication tag for 16 buffers
 *
 * @param[out] pa_tag       Array of authentication tag pointers
 * @param[in] tag_len       Array of tag lengths
 * @param[in/out] p_context SM4-CCM context
 *
 * @return Bitmask of operation status
 */
MBXAPI(mbx_status16,
       mbx_sm4_ccm_get_tag_mb16,
       (int8u * pa_tag[SM4_LINES], const int tag_len[SM4_LINES], SM4_CCM_CTX_mb16* p_context))
/*
 * Encrypts 16 buffers with SM4-CCM.
 *
 * @param[out] pa_out       Array of ciphertext pointers
 * @param[in] pa_in         Array of plaintext pointers
 * @param[in] in_len        Array of plaintext lengths
 * @param[in/out] p_context SM4-CCM context
 *
 * @return Bitmask of operation status
 */
MBXAPI(mbx_status16,
       mbx_sm4_ccm_encrypt_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* const pa_in[SM4_LINES],
        const int in_len[SM4_LINES],
        SM4_CCM_CTX_mb16* p_context))
/*
 * Decrypts 16 buffers with SM4-CCM.
 *
 * @param[out] pa_out       Array of plaintext pointers
 * @param[in] pa_in         Array of ciphertext pointers
 * @param[in] in_len        Array of ciphertext lengths
 * @param[in/out] p_context SM4-CCM context
 *
 * @return Bitmask of operation status
 */
MBXAPI(mbx_status16,
       mbx_sm4_ccm_decrypt_mb16,
       (int8u * pa_out[SM4_LINES],
        const int8u* const pa_in[SM4_LINES],
        const int in_len[SM4_LINES],
        SM4_CCM_CTX_mb16* p_context))

#endif /* SM4_CCM_H */
