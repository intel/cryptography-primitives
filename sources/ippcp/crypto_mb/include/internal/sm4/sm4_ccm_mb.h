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

#include <crypto_mb/sm4_ccm.h>

#include <internal/sm4/sm4_mb.h>

#ifndef SM4_CCM_MB_H
#define SM4_CCM_MB_H

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
// Internal functions
*/

#if (_MBX >= _MBX_K1)

/*
 * Set IV for 16 buffers in SM4-CCM context
 *
 * @param[in] pa_iv         Array of IVs
 * @param[in] iv_len        Array of IV lengths
 * @param[in] mb_mask       Bitmask selecting which lines to update
 * @param[in/out] p_context SM4-CCM context
 *
 */
EXTERN_C void sm4_ccm_update_iv_mb16(const int8u* const pa_iv[SM4_LINES],
                                     const int iv_len[SM4_LINES],
                                     __mmask16 mb_mask,
                                     SM4_CCM_CTX_mb16* p_context);
/*
 * Set message lengths for 16 buffers in SM4-CCM context
 *
 * @param[in] msg_len           Array of total message lengths
 * @param[in] mb_mask           Bitmask selecting which lines to update
 * @param[in/out] p_context     SM4-CCM context
 *
 */
EXTERN_C void sm4_ccm_set_msg_len_mb16(const int64u msg_len[SM4_LINES],
                                       __mmask16 mb_mask,
                                       SM4_CCM_CTX_mb16* p_context);

/*
 * Set authentication tag lengths for 16 buffers in SM4-CCM context
 *
 * @param[in] tag_len           Array of authentication tag lengths
 * @param[in] mb_mask           Bitmask selecting which lines to update
 * @param[in/out] p_context     SM4-CCM context
 *
 */
EXTERN_C void sm4_ccm_set_tag_len_mb16(const int tag_len[SM4_LINES],
                                       __mmask16 mb_mask,
                                       SM4_CCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 sm4_ccm_update_aad_mb16(const int8u* const pa_aad[SM4_LINES],
                                              const int aad_len[SM4_LINES],
                                              __mmask16 mb_mask,
                                              SM4_CCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 sm4_ccm_encrypt_mb16(int8u* pa_out[SM4_LINES],
                                           const int8u* const pa_in[SM4_LINES],
                                           const int in_len[SM4_LINES],
                                           __mmask16 mb_mask,
                                           SM4_CCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 sm4_ccm_decrypt_mb16(int8u* pa_out[SM4_LINES],
                                           const int8u* const pa_in[SM4_LINES],
                                           const int in_len[SM4_LINES],
                                           __mmask16 mb_mask,
                                           SM4_CCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 sm4_ccm_get_tag_mb16(int8u* pa_out[SM4_LINES],
                                           const int tag_len[SM4_LINES],
                                           __mmask16 mb_mask,
                                           SM4_CCM_CTX_mb16* p_context);

mbx_status16 internal_avx512_sm4_ccm_init_mb16(const sm4_key* const pa_key[SM4_LINES],
                                               const int8u* const pa_iv[SM4_LINES],
                                               const int iv_len[SM4_LINES],
                                               const int tag_len[SM4_LINES],
                                               const int64u msg_len[SM4_LINES],
                                               SM4_CCM_CTX_mb16* p_context,
                                               __mmask16 mb_mask);
#endif /* #if (_MBX>=_MBX_K1) */

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/* Context accessors */

#define SM4_CCM_CONTEXT_MSG_LEN(context)       ((context)->msg_len)
#define SM4_CCM_CONTEXT_PROCESSED_LEN(context) ((context)->total_processed_len)
#define SM4_CCM_CONTEXT_TAG_LEN(context)       ((context)->tag_len)
#define SM4_CCM_CONTEXT_IV_LEN(context)        ((context)->iv_len)
#define SM4_CCM_CONTEXT_CTR0(context)          ((context)->ctr0)
#define SM4_CCM_CONTEXT_CTR(context)           ((context)->ctr)
#define SM4_CCM_CONTEXT_HASH(context)          ((context)->hash)

#define SM4_CCM_CONTEXT_KEY(context)   (&((context)->key_sched))
#define SM4_CCM_CONTEXT_STATE(context) ((context)->state)

/* Calculate offsets for accessing blocks in buffers */

#define REG_SIZE_BITS  (512)
#define REG_SIZE_BYTES (REG_SIZE_BITS / 8) /* Register size in bytes */

#define SLOTS_PER_BLOCK (SM4_BLOCK_SIZE / SM4_CCM_CONTEXT_BUFFER_SLOT_SIZE_BYTES)
#define BLOCKS_PER_REG  (REG_SIZE_BYTES / SM4_BLOCK_SIZE)

#define BUFFER_BLOCK_NUM(buffer, n) ((buffer) + SLOTS_PER_BLOCK * (n))
#define BUFFER_REG_NUM(buffer, n)   ((buffer) + SLOTS_PER_BLOCK * BLOCKS_PER_REG * (n))

/* Internal macros */

#define sm4_ccm_clear_buffer(p_buffer) storeu((void*)(p_buffer), setzero());

#define SM4_CCM_CLEAR_BUFFER(p_buffer)                     \
    {                                                      \
        sm4_ccm_clear_buffer(BUFFER_REG_NUM(p_buffer, 0)); \
        sm4_ccm_clear_buffer(BUFFER_REG_NUM(p_buffer, 1)); \
        sm4_ccm_clear_buffer(BUFFER_REG_NUM(p_buffer, 2)); \
        sm4_ccm_clear_buffer(BUFFER_REG_NUM(p_buffer, 3)); \
    }

#define SM4_CCM_CLEAR_LEN(p_len)     \
    {                                \
        sm4_ccm_clear_buffer(p_len); \
    }

#endif // SM4_CCM_MB_H
