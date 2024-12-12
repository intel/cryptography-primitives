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

#include <crypto_mb/sm4_gcm.h>

#include <internal/sm4/sm4_mb.h>

#ifndef SM4_GCM_MB_H
#define SM4_GCM_MB_H

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
// Constant from NIST Special Publication 800-38D
// (Recommendation for GCMmode, p.5.2.1.1 Input Data)
// len(P) <= 2^39-256 bits
*/
static const int64u MAX_TXT_LEN = ((int64u)1 << 36) - 32; // length in bytes

/*
// Internal functions
*/

#if (_MBX >= _MBX_K1)

EXTERN_C void sm4_gcm_ghash_mul_single_block_mb16(__m512i* data_blocks[], __m512i* hashkeys[]);

EXTERN_C void sm4_gcm_update_ghash_full_blocks_mb16(
    __m128i ghash[SM4_LINES],
    const int8u* const pa_input[SM4_LINES],
    __m512i* input_len,
    __m128i hashkey[SM4_GCM_HASHKEY_PWR_NUM][SM4_LINES],
    __mmask16 mb_mask);

EXTERN_C void sm4_gcm_update_ghash_partial_blocks_mb16(__m128i ghash[SM4_LINES],
                                                       const int8u* const pa_input[SM4_LINES],
                                                       __m512i* input_len,
                                                       __m128i hashkey[SM4_LINES],
                                                       __mmask16 mb_mask);

EXTERN_C void sm4_gcm_precompute_hashkey_mb16(const mbx_sm4_key_schedule* key_sched,
                                              SM4_GCM_CTX_mb16* p_context);

EXTERN_C __mmask16 sm4_gcm_update_iv_mb16(const int8u* const pa_iv[SM4_LINES],
                                          const int iv_len[SM4_LINES],
                                          __mmask16 mb_mask,
                                          SM4_GCM_CTX_mb16* p_context);

EXTERN_C void sm4_gcm_finalize_iv_mb16(const int8u* const pa_iv[SM4_LINES],
                                       __mmask16 mb_mask,
                                       SM4_GCM_CTX_mb16* p_context);

EXTERN_C __mmask16 sm4_gcm_update_aad_mb16(const int8u* const pa_aad[SM4_LINES],
                                           const int aad_len[SM4_LINES],
                                           __mmask16 mb_mask,
                                           SM4_GCM_CTX_mb16* p_context);

EXTERN_C void sm4_encrypt_j0_mb16(SM4_GCM_CTX_mb16* p_context);

EXTERN_C void sm4_gctr_kernel_mb16(int8u* pa_out[SM4_LINES],
                                   const int8u* const pa_inp[SM4_LINES],
                                   const int len[SM4_LINES],
                                   const int32u* key_sched[SM4_ROUNDS],
                                   __mmask16 mb_mask,
                                   SM4_GCM_CTX_mb16* p_context);

EXTERN_C __mmask16 sm4_gcm_encrypt_mb16(int8u* pa_out[SM4_LINES],
                                        const int8u* const pa_in[SM4_LINES],
                                        const int in_len[SM4_LINES],
                                        __mmask16 mb_mask,
                                        SM4_GCM_CTX_mb16* p_context);

EXTERN_C __mmask16 sm4_gcm_decrypt_mb16(int8u* pa_out[SM4_LINES],
                                        const int8u* const pa_in[SM4_LINES],
                                        const int in_len[SM4_LINES],
                                        __mmask16 mb_mask,
                                        SM4_GCM_CTX_mb16* p_context);

EXTERN_C mbx_status16 sm4_gcm_get_tag_mb16(int8u* pa_out[SM4_LINES],
                                           const int tag_len[SM4_LINES],
                                           __mmask16 mb_mask,
                                           SM4_GCM_CTX_mb16* p_context);

mbx_status16 internal_avx512_sm4_gcm_init_mb16(const sm4_key* const pa_key[SM4_LINES],
                                               const int8u* const pa_iv[SM4_LINES],
                                               const int iv_len[SM4_LINES],
                                               SM4_GCM_CTX_mb16* p_context,
                                               __mmask16 mb_mask_rearranged,
                                               __mmask16 mb_mask);

__MBX_INLINE __m512i inc_block32(__m512i x, const int8u* increment)
{
    return mask_add_epi32(x, 0x1111, x, M512(increment));
}

static __ALIGN64 const int8u initialInc[] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

#endif /* #if (_MBX>=_MBX_K1) */

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/* Context accessors */

#define SM4_GCM_CONTEXT_HASHKEY(context) ((p_context)->hashkey)
#define SM4_GCM_CONTEXT_J0(context)      ((p_context)->j0)
#define SM4_GCM_CONTEXT_GHASH(context)   ((p_context)->ghash)
#define SM4_GCM_CONTEXT_CTR(context)     ((p_context)->ctr)

#define SM4_GCM_CONTEXT_LEN(context) ((p_context)->len)

#define SM4_GCM_CONTEXT_KEY(context) (&((p_context)->key_sched))

#define SM4_GCM_CONTEXT_STATE(context) ((p_context)->state)

/* Calculate offsets for accessing blocks in buffers */

#define REG_SIZE_BITS  (512)
#define REG_SIZE_BYTES (REG_SIZE_BITS / 8) /* Register size in bytes */

#define SLOTS_PER_BLOCK (SM4_BLOCK_SIZE / SM4_GCM_CONTEXT_BUFFER_SLOT_SIZE_BYTES)
#define BLOCKS_PER_REG  (REG_SIZE_BYTES / SM4_BLOCK_SIZE)

#define BUFFER_BLOCK_NUM(buffer, n) ((buffer) + SLOTS_PER_BLOCK * (n))
#define BUFFER_REG_NUM(buffer, n)   ((buffer) + SLOTS_PER_BLOCK * (BLOCKS_PER_REG * (n)))

/* Internal macros */

#define sm4_gcm_clear_buffer(p_buffer) storeu((void*)(p_buffer), setzero());

#define SM4_GCM_CLEAR_BUFFER(p_buffer)                     \
    {                                                      \
        sm4_gcm_clear_buffer(BUFFER_REG_NUM(p_buffer, 0)); \
        sm4_gcm_clear_buffer(BUFFER_REG_NUM(p_buffer, 1)); \
        sm4_gcm_clear_buffer(BUFFER_REG_NUM(p_buffer, 2)); \
        sm4_gcm_clear_buffer(BUFFER_REG_NUM(p_buffer, 3)); \
    }

#define SM4_GCM_CLEAR_LEN(p_len)     \
    {                                \
        sm4_gcm_clear_buffer(p_len); \
    }

/* Constants */

/* GCM polynomials for reduction */
static __ALIGN64 const int64u gcm_poly[] = { 0x0000000000000001, 0xC200000000000000,
                                             0x0000000000000001, 0xC200000000000000,
                                             0x0000000000000001, 0xC200000000000000,
                                             0x0000000000000001, 0xC200000000000000 };

static __ALIGN64 const int64u gcm_poly2[] = { 0x00000001C2000000, 0xC200000000000000,
                                              0x00000001C2000000, 0xC200000000000000,
                                              0x00000001C2000000, 0xC200000000000000,
                                              0x00000001C2000000, 0xC200000000000000 };

/* */
static __ALIGN64 const int64u two_one[] = { 0x0000000000000001, 0x0000000100000000,
                                            0x0000000000000001, 0x0000000100000000,
                                            0x0000000000000001, 0x0000000100000000,
                                            0x0000000000000001, 0x0000000100000000 };

/* Constant for IV of 12 bytes size finalization */
static __ALIGN64 const int64u one_f[] = { 0x0000000000000000, 0x0100000000000000,
                                          0x0000000000000000, 0x0100000000000000,
                                          0x0000000000000000, 0x0100000000000000,
                                          0x0000000000000000, 0x0100000000000000 };

static __ALIGN64 const int64u bytes_to_bits_shift[] = { 0x0000000000000003, 0x0000000000000000 };

static const int rearrangeOrder[] = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };

/* Need to rearrange input pointers and lengths to keep it in the same layout with hashkeys */
#define rearrange(to, from) \
    (to)[0]  = (from)[0];   \
    (to)[1]  = (from)[4];   \
    (to)[2]  = (from)[8];   \
    (to)[3]  = (from)[12];  \
    (to)[4]  = (from)[1];   \
    (to)[5]  = (from)[5];   \
    (to)[6]  = (from)[9];   \
    (to)[7]  = (from)[13];  \
    (to)[8]  = (from)[2];   \
    (to)[9]  = (from)[6];   \
    (to)[10] = (from)[10];  \
    (to)[11] = (from)[14];  \
    (to)[12] = (from)[3];   \
    (to)[13] = (from)[7];   \
    (to)[14] = (from)[11];  \
    (to)[15] = (from)[15];

#endif // SM4_GCM_MB_H
