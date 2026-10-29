/*************************************************************************
* Copyright (C) 2026 Intel Corporation
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

/*
//     Purpose:  SM4-NI (VSM4RNDS4) multi-buffer kernels for the Intel® AVX10.2 tier.
//
//  This is the ONLY translation unit compiled with Intel® AVX10.2 enabled. Nothing
//  here may be called without internal_sm4ni_dispatch() returning true first, and no
//  Intel® AVX10.2 intrinsic may be added to any other file - the rest of the k1
//  objects are built for Intel® AVX-512 and must stay loadable on those CPUs.
//
//  VSM4RNDS4 applies four SM4 rounds per 128-bit lane and takes each lane's round
//  keys from the corresponding lane of the second source. One zmm therefore holds
//  SM4_NI_LANES buffers, one block each, under that many independent keys - which is
//  what makes the instruction usable for multi-buffer: no cross-block transpose and
//  no S-box synthesis, unlike the GFNI kernels in this directory.
*/

#include <internal/common/ifma_defs.h>
#include <internal/rsa/ifma_rsa_arith.h>
#include <internal/sm4/sm4_mb.h>

#if (_MBX >= _MBX_K1) && defined(MBX_SM4NI_ENABLED)

/* one 128-bit lane per buffer, so a zmm carries this many of them */
#define SM4_NI_LANES (4)
/* the 16 mb16 lines, taken SM4_NI_LANES at a time */
#define SM4_NI_GROUPS (SM4_LINES / SM4_NI_LANES)
/* VSM4RNDS4 does 4 rounds, so 8 of them cover all SM4_ROUNDS */
#define SM4_NI_KEY_STEPS (SM4_ROUNDS / 4)
/* consecutive blocks per buffer the bulk paths take per pass; with SM4_NI_GROUPS this is
   how many independent VSM4RNDS4 chains they keep in flight */
#define SM4_NI_SLOTS (4)

/*
// Aliases for permutations sm4_mb.h already defines, so the tables live in one place while
// the names say what each one means here:
//
//   shuf_in     byte-reverse each 32-bit word in a lane -> the cipher's input form
//   shuf_out    full 16-byte reverse -> undoes the round-order swap on output, and
//               converts a counter between the caller's byte string and numeric form
//   shuf_ctr_in numeric counter straight to cipher input form (shuf_out then shuf_in)
*/
#define sm4_ni_shuf_in     swapBytes
#define sm4_ni_shuf_out    swapEndianness
#define sm4_ni_shuf_ctr_in swapWordsOrder

/* XTS: the GF(2^128) reduction polynomial, in the low qword of each 128-bit lane */
/* clang-format off */
static __ALIGN64 const int64u sm4_ni_xts_poly[] = { 0x87, 0, 0x87, 0, 0x87, 0, 0x87, 0 };
/* clang-format on */

/*
// Repack the round keys from the public key_sched[round][line] layout into the
// lane-packed form VSM4RNDS4 needs: round_keys[group][step] holds, in lane l, the four
// round keys of step for buffer (4*group + l).
//
// For decryption SM4 is its own inverse with the round keys reversed, so the step
// walks the schedule downward.
//
// The kernels get the schedule through the int32u* key_sched[] parameter the GFNI
// kernels use, so each caller casts it back to the mbx_sm4_key_schedule it really is.
*/
static void sm4_ni_repack_keys(__m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS],
                               const mbx_sm4_key_schedule* key_sched,
                               int operation)
{
    /* staging for one zmm of round keys; held outside the loops so it is wiped once */
    __ALIGN64 int32u lanes[SM4_LINES];
    /* operation is +1 for encryption and -1 for decryption, so it doubles as the direction
       the schedule is walked in: forward from round 0, or backward from the last round */
    const int first_round = (SM4_ENC == operation) ? 0 : (SM4_ROUNDS - 1);

    for (int group = 0; group < SM4_NI_GROUPS; group++) {
        for (int step = 0; step < SM4_NI_KEY_STEPS; step++) {
            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                for (int rnd = 0; rnd < 4; rnd++) {
                    const int round_index = first_round + operation * (4 * step + rnd);

                    lanes[4 * lane + rnd] = (*key_sched)[round_index][4 * group + lane];
                }
            }
            round_keys[group][step] = _mm512_load_si512(lanes);
        }
    }

    zero_mb8((int64u(*)[8])lanes, 1);
}

/*
// Load the current block of each of a group's buffers into the lanes of a zmm, in plain
// byte order. Lanes whose bit is clear in lane_mask are left zero - those buffers have
// no block left. The chained modes need this form so they can xor against a chain value
// before the byte swap; ECB uses the wrapper below, which swaps immediately.
//
// A masked-off buffer may be NULL - SM4-CCM passes NULL for lines it is not processing -
// so this form does no pointer arithmetic. Only the _at() forms, used when every lane is
// active, add an offset.
*/
__MBX_INLINE __m512i sm4_ni_gather_raw_4x1(const int8u* const input[SM4_NI_LANES],
                                           __mmask8 lane_mask)
{
    const __m128i lane0 = _mm_maskz_loadu_epi64((__mmask8)(0x3 * ((lane_mask >> 0) & 1)), input[0]);
    const __m128i lane1 = _mm_maskz_loadu_epi64((__mmask8)(0x3 * ((lane_mask >> 1) & 1)), input[1]);
    const __m128i lane2 = _mm_maskz_loadu_epi64((__mmask8)(0x3 * ((lane_mask >> 2) & 1)), input[2]);
    const __m128i lane3 = _mm_maskz_loadu_epi64((__mmask8)(0x3 * ((lane_mask >> 3) & 1)), input[3]);
    __m512i block       = _mm512_castsi128_si512(lane0);

    block = _mm512_inserti64x2(block, lane1, 1);
    block = _mm512_inserti64x2(block, lane2, 2);
    block = _mm512_inserti64x2(block, lane3, 3);

    return block;
}

/* As above, converted straight to the cipher's input form */
__MBX_INLINE __m512i sm4_ni_gather_4x1(const int8u* const input[SM4_NI_LANES], __mmask8 lane_mask)
{
    return _mm512_shuffle_epi8(sm4_ni_gather_raw_4x1(input, lane_mask),
                               _mm512_load_si512(sm4_ni_shuf_in));
}

/* Load block number 'slot' from all four buffers, in plain byte order */
__MBX_INLINE __m512i sm4_ni_gather_raw_4x1_at(const int8u* const input[SM4_NI_LANES], int slot)
{
    const int offset    = slot * SM4_BLOCK_SIZE;
    const __m128i lane0 = _mm_maskz_loadu_epi64(0x3, input[0] + offset);
    const __m128i lane1 = _mm_maskz_loadu_epi64(0x3, input[1] + offset);
    const __m128i lane2 = _mm_maskz_loadu_epi64(0x3, input[2] + offset);
    const __m128i lane3 = _mm_maskz_loadu_epi64(0x3, input[3] + offset);
    __m512i block       = _mm512_castsi128_si512(lane0);

    block = _mm512_inserti64x2(block, lane1, 1);
    block = _mm512_inserti64x2(block, lane2, 2);
    block = _mm512_inserti64x2(block, lane3, 3);

    return block;
}

/* As above, converted straight to the cipher's input form */
__MBX_INLINE __m512i sm4_ni_gather_4x1_at(const int8u* const input[SM4_NI_LANES], int slot)
{
    return _mm512_shuffle_epi8(sm4_ni_gather_raw_4x1_at(input, slot),
                               _mm512_load_si512(sm4_ni_shuf_in));
}

/*
// Lane mask for a group's IV load. Callers are allowed to pass a NULL IV pointer for a
// line they are not processing - SM4-CCM does exactly that - so a line with no blocks
// must be masked out rather than loaded.
*/
__MBX_INLINE __mmask8 sm4_ni_iv_lane_mask(const int num_blocks[SM4_LINES], int group)
{
    __mmask8 lane_mask = 0;

    for (int lane = 0; lane < SM4_NI_LANES; lane++)
        if (num_blocks[4 * group + lane] > 0)
            lane_mask |= (__mmask8)(1 << lane);

    return lane_mask;
}

/*
// XTS tweak step: T <- T * alpha in GF(2^128) with the modulus x^128 + x^7 + x^2 + x + 1,
// i.e. a 128-bit left shift by one with 0x87 folded back in on overflow.
//
// Every 128-bit lane holds the tweak of a different buffer, so all four chains have to
// advance independently - the byte shifts below stay inside their own lane, which is what
// makes this layout work at all.
*/
__MBX_INLINE __m512i sm4_ni_tweak_mul(__m512i tweak)
{
    const __m512i poly = _mm512_load_si512(sm4_ni_xts_poly);
    const __m512i top  = _mm512_srli_epi64(tweak, 63); /* top bit of each qword */
    const __m512i shl  = _mm512_slli_epi64(tweak, 1);
    /* the low qword's carry enters the high qword; the high qword's carry is reduced */
    const __m512i carry_in  = _mm512_bslli_epi128(top, 8);
    const __m512i carry_out = _mm512_bsrli_epi128(top, 8);

    return _mm512_xor_si512(_mm512_or_si512(shl, carry_in),
                            _mm512_clmulepi64_epi128(carry_out, poly, 0x00));
}

/*
// Add 'increment' to each 128-bit lane, big-endian, carrying from the low qword into the
// high one. The lanes hold numeric counters (see sm4_ni_ctr_load), so the low qword is
// the least significant half.
*/
__MBX_INLINE __m512i sm4_ni_ctr_inc(__m512i ctr, int32u increment)
{
    const __m512i sum = _mm512_add_epi64(ctr, _mm512_maskz_set1_epi64(0x55, (long long)increment));
    /* a lane's low qword wrapped -> carry 1 into its high qword */
    const __mmask8 carry = (__mmask8)(_mm512_cmplt_epu64_mask(sum, ctr) << 1);

    return _mm512_add_epi64(sum, _mm512_mask_set1_epi64(_mm512_setzero_si512(), carry, 1));
}

/* Same, for the single 128-bit counter written back to the caller */
__MBX_INLINE __m128i sm4_ni_ctr_inc128(__m128i ctr, int32u increment)
{
    const __m128i sum    = _mm_add_epi64(ctr, _mm_maskz_loadu_epi32(1, &increment));
    const __mmask8 carry = (__mmask8)(_mm_cmplt_epu64_mask(sum, ctr) << 1);

    return _mm_add_epi64(sum, _mm_mask_set1_epi64(_mm_setzero_si128(), carry, 1));
}

/* Widen a 4-bit lane mask to the qword mask that selects the same 128-bit lanes */
__MBX_INLINE __mmask8 sm4_ni_lane_to_qword_mask(__mmask8 lane_mask)
{
    return (__mmask8)((0x3 * ((lane_mask >> 0) & 1)) | (0xC * ((lane_mask >> 1) & 1)) |
                      (0x30 * ((lane_mask >> 2) & 1)) | (0xC0 * ((lane_mask >> 3) & 1)));
}

/* Store each lane back to the current block of its own buffer, taking it in plain byte
   order. Masked-off lanes are not written, and like the gather, no pointer arithmetic. */
__MBX_INLINE void sm4_ni_scatter_raw_4x1(__m512i z,
                                         int8u* const out[SM4_NI_LANES],
                                         __mmask8 lane_mask)
{
    _mm_mask_storeu_epi64(out[0],
                          (__mmask8)(0x3 * ((lane_mask >> 0) & 1)),
                          _mm512_extracti64x2_epi64(z, 0));
    _mm_mask_storeu_epi64(out[1],
                          (__mmask8)(0x3 * ((lane_mask >> 1) & 1)),
                          _mm512_extracti64x2_epi64(z, 1));
    _mm_mask_storeu_epi64(out[2],
                          (__mmask8)(0x3 * ((lane_mask >> 2) & 1)),
                          _mm512_extracti64x2_epi64(z, 2));
    _mm_mask_storeu_epi64(out[3],
                          (__mmask8)(0x3 * ((lane_mask >> 3) & 1)),
                          _mm512_extracti64x2_epi64(z, 3));
}

/* As above, taking the cipher's output form and undoing the round-order swap */
__MBX_INLINE void sm4_ni_scatter_4x1(__m512i z, int8u* const out[SM4_NI_LANES], __mmask8 lane_mask)
{
    sm4_ni_scatter_raw_4x1(_mm512_shuffle_epi8(z, _mm512_load_si512(sm4_ni_shuf_out)),
                           out,
                           lane_mask);
}

/* Store each lane to block 'slot' of all four buffers, taking it in plain byte order */
__MBX_INLINE void sm4_ni_scatter_raw_4x1_at(__m512i z, int8u* const out[SM4_NI_LANES], int slot)
{
    const int offset = slot * SM4_BLOCK_SIZE;

    _mm_mask_storeu_epi64(out[0] + offset, 0x3, _mm512_extracti64x2_epi64(z, 0));
    _mm_mask_storeu_epi64(out[1] + offset, 0x3, _mm512_extracti64x2_epi64(z, 1));
    _mm_mask_storeu_epi64(out[2] + offset, 0x3, _mm512_extracti64x2_epi64(z, 2));
    _mm_mask_storeu_epi64(out[3] + offset, 0x3, _mm512_extracti64x2_epi64(z, 3));
}

/* As above, taking the cipher's output form and undoing the round-order swap */
__MBX_INLINE void sm4_ni_scatter_4x1_at(__m512i z, int8u* const out[SM4_NI_LANES], int slot)
{
    sm4_ni_scatter_raw_4x1_at(_mm512_shuffle_epi8(z, _mm512_load_si512(sm4_ni_shuf_out)),
                              out,
                              slot);
}

/*
// All 32 rounds over the group registers, interleaved within each round so that
// independent VSM4RNDS4 chains stay in flight and hide the instruction's latency.
//
// The number of chains is what sets throughput, and it takes more than SM4_NI_GROUPS of
// them to saturate the unit, so the bulk path below works on SM4_NI_SLOTS block slots at
// once - SM4_NI_GROUPS * SM4_NI_SLOTS registers - and only the tail runs the narrow form.
*/
#define SM4_NI_ROUNDS_4(Z, RKV)                                     \
    {                                                               \
        for (int step = 0; step < SM4_NI_KEY_STEPS; step++) {       \
            (Z)[0] = _mm512_sm4rnds4_epi32((Z)[0], (RKV)[0][step]); \
            (Z)[1] = _mm512_sm4rnds4_epi32((Z)[1], (RKV)[1][step]); \
            (Z)[2] = _mm512_sm4rnds4_epi32((Z)[2], (RKV)[2][step]); \
            (Z)[3] = _mm512_sm4rnds4_epi32((Z)[3], (RKV)[3][step]); \
        }                                                           \
    }

#define SM4_NI_ROUNDS_16(Z, RKV)                                                          \
    {                                                                                     \
        for (int step = 0; step < SM4_NI_KEY_STEPS; step++) {                             \
            for (int group = 0; group < SM4_NI_GROUPS; group++) {                         \
                (Z)[group][0] = _mm512_sm4rnds4_epi32((Z)[group][0], (RKV)[group][step]); \
                (Z)[group][1] = _mm512_sm4rnds4_epi32((Z)[group][1], (RKV)[group][step]); \
                (Z)[group][2] = _mm512_sm4rnds4_epi32((Z)[group][2], (RKV)[group][step]); \
                (Z)[group][3] = _mm512_sm4rnds4_epi32((Z)[group][3], (RKV)[group][step]); \
            }                                                                             \
        }                                                                                 \
    }

mbx_status16 sm4_ni_ecb_kernel_mb16(int8u* pa_out[SM4_LINES],
                                    const int8u* pa_inp[SM4_LINES],
                                    const int len[SM4_LINES],
                                    const int32u* key_sched[SM4_ROUNDS],
                                    __mmask16 mb_mask,
                                    int operation)
{
    mbx_status16 status = 0;
    __ALIGN64 __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];
    int num_blocks[SM4_LINES];
    int max_blocks = 0;
    int min_blocks = 0;

    sm4_ni_repack_keys(round_keys, (const mbx_sm4_key_schedule*)key_sched, operation);

    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        loc_inp[buf_no]    = pa_inp[buf_no];
        loc_out[buf_no]    = pa_out[buf_no];
        num_blocks[buf_no] = ((mb_mask >> buf_no) & 1) ? len[buf_no] / SM4_BLOCK_SIZE : 0;
        if (num_blocks[buf_no] > max_blocks)
            max_blocks = num_blocks[buf_no];
        if (0 == buf_no || num_blocks[buf_no] < min_blocks)
            min_blocks = num_blocks[buf_no];
    }

    int block = 0;

    /* Bulk path: while every line still has SM4_NI_SLOTS blocks left, take that many
       from each. 16 registers in flight, and no masking needed. */
    for (; block + SM4_NI_SLOTS <= min_blocks; block += SM4_NI_SLOTS) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS][SM4_NI_SLOTS];

        for (int group = 0; group < SM4_NI_GROUPS; group++)
            for (int slot = 0; slot < SM4_NI_SLOTS; slot++)
                z[group][slot] = sm4_ni_gather_4x1_at(&loc_inp[4 * group], slot);

        SM4_NI_ROUNDS_16(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            for (int slot = 0; slot < SM4_NI_SLOTS; slot++)
                sm4_ni_scatter_4x1_at(z[group][slot], &loc_out[4 * group], slot);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                loc_inp[4 * group + lane] += SM4_NI_SLOTS * SM4_BLOCK_SIZE;
                loc_out[4 * group + lane] += SM4_NI_SLOTS * SM4_BLOCK_SIZE;
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(__m512i));
    }

    /* Tail: the lines have run ragged, so fall back to one block per line per pass
       and mask off the lines that are already done. */
    for (; block < max_blocks; block++) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];
        __mmask8 lane_mask[SM4_NI_GROUPS];

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            lane_mask[group] = 0;
            for (int lane = 0; lane < SM4_NI_LANES; lane++)
                if (block < num_blocks[4 * group + lane])
                    lane_mask[group] |= (__mmask8)(1 << lane);

            z[group] = sm4_ni_gather_4x1(&loc_inp[4 * group], lane_mask[group]);
        }

        SM4_NI_ROUNDS_4(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            sm4_ni_scatter_4x1(z[group], &loc_out[4 * group], lane_mask[group]);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                if (block < num_blocks[4 * group + lane]) {
                    loc_inp[4 * group + lane] += SM4_BLOCK_SIZE;
                    loc_out[4 * group + lane] += SM4_BLOCK_SIZE;
                }
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
    }

    zero_mb8((int64u(*)[8])round_keys, sizeof(round_keys) / sizeof(__m512i));

    return status;
}

/*
// CBC and CFB encryption chain block n+1 on the ciphertext of block n, so unlike ECB
// they cannot batch several blocks of a line into one pass: only SM4_NI_GROUPS chains
// are ever in flight, so they do not reach the throughput of the bulk paths.
//
// Lines run to different lengths. Once a line is out of blocks its chain register must
// keep its last value instead of absorbing whatever the masked-off gather returned, so
// the chain update blends only the lanes that are still active.
*/
mbx_status16 sm4_ni_cbc_enc_kernel_mb16(int8u* pa_out[SM4_LINES],
                                        const int8u* pa_inp[SM4_LINES],
                                        const int len[SM4_LINES],
                                        const int32u* key_sched[SM4_ROUNDS],
                                        __mmask16 mb_mask,
                                        const int8u* pa_iv[SM4_LINES])
{
    mbx_status16 status = 0;
    __ALIGN64 __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 __m512i chain[SM4_NI_GROUPS];
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];
    int num_blocks[SM4_LINES];
    int max_blocks = 0;

    sm4_ni_repack_keys(round_keys, (const mbx_sm4_key_schedule*)key_sched, SM4_ENC);

    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        loc_inp[buf_no]    = pa_inp[buf_no];
        loc_out[buf_no]    = pa_out[buf_no];
        num_blocks[buf_no] = ((mb_mask >> buf_no) & 1) ? len[buf_no] / SM4_BLOCK_SIZE : 0;
        if (num_blocks[buf_no] > max_blocks)
            max_blocks = num_blocks[buf_no];
    }

    /* the IV is the first block's chain value, in plain byte order */
    for (int group = 0; group < SM4_NI_GROUPS; group++)
        chain[group] =
            sm4_ni_gather_raw_4x1(&pa_iv[4 * group], sm4_ni_iv_lane_mask(num_blocks, group));

    for (int block = 0; block < max_blocks; block++) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];
        __mmask8 lane_mask[SM4_NI_GROUPS];

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            lane_mask[group] = 0;
            for (int lane = 0; lane < SM4_NI_LANES; lane++)
                if (block < num_blocks[4 * group + lane])
                    lane_mask[group] |= (__mmask8)(1 << lane);

            /* xor the plaintext with the previous ciphertext, then swap into cipher form */
            z[group] = _mm512_shuffle_epi8(
                _mm512_xor_si512(sm4_ni_gather_raw_4x1(&loc_inp[4 * group], lane_mask[group]),
                                 chain[group]),
                _mm512_load_si512(sm4_ni_shuf_in));
        }

        SM4_NI_ROUNDS_4(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            const __m512i cipher_text =
                _mm512_shuffle_epi8(z[group], _mm512_load_si512(sm4_ni_shuf_out));

            chain[group] = _mm512_mask_blend_epi64(sm4_ni_lane_to_qword_mask(lane_mask[group]),
                                                   chain[group],
                                                   cipher_text);
            sm4_ni_scatter_raw_4x1(cipher_text, &loc_out[4 * group], lane_mask[group]);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                if (block < num_blocks[4 * group + lane]) {
                    loc_inp[4 * group + lane] += SM4_BLOCK_SIZE;
                    loc_out[4 * group + lane] += SM4_BLOCK_SIZE;
                }
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
    }

    zero_mb8((int64u(*)[8])round_keys, sizeof(round_keys) / sizeof(__m512i));
    zero_mb8((int64u(*)[8])chain, sizeof(chain) / sizeof(chain[0]));

    return status;
}

/* CFB128 encryption. Same chain as CBC, except the cipher runs on the previous ciphertext to
   make a keystream block and the plaintext is xored afterwards. */
mbx_status16 sm4_ni_cfb128_enc_kernel_mb16(int8u* pa_out[SM4_LINES],
                                           const int8u* pa_inp[SM4_LINES],
                                           const int len[SM4_LINES],
                                           const int32u* key_sched[SM4_ROUNDS],
                                           const int8u* pa_iv[SM4_LINES],
                                           __mmask16 mb_mask)
{
    mbx_status16 status = 0;
    __ALIGN64 __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 __m512i chain[SM4_NI_GROUPS];
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];
    int num_blocks[SM4_LINES];
    int max_blocks = 0;

    sm4_ni_repack_keys(round_keys, (const mbx_sm4_key_schedule*)key_sched, SM4_ENC);

    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        loc_inp[buf_no]    = pa_inp[buf_no];
        loc_out[buf_no]    = pa_out[buf_no];
        num_blocks[buf_no] = ((mb_mask >> buf_no) & 1) ? len[buf_no] / SM4_BLOCK_SIZE : 0;
        if (num_blocks[buf_no] > max_blocks)
            max_blocks = num_blocks[buf_no];
    }

    for (int group = 0; group < SM4_NI_GROUPS; group++)
        chain[group] =
            sm4_ni_gather_raw_4x1(&pa_iv[4 * group], sm4_ni_iv_lane_mask(num_blocks, group));

    for (int block = 0; block < max_blocks; block++) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];
        __mmask8 lane_mask[SM4_NI_GROUPS];

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            lane_mask[group] = 0;
            for (int lane = 0; lane < SM4_NI_LANES; lane++)
                if (block < num_blocks[4 * group + lane])
                    lane_mask[group] |= (__mmask8)(1 << lane);

            z[group] = _mm512_shuffle_epi8(chain[group], _mm512_load_si512(sm4_ni_shuf_in));
        }

        SM4_NI_ROUNDS_4(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            const __m512i keystream =
                _mm512_shuffle_epi8(z[group], _mm512_load_si512(sm4_ni_shuf_out));
            const __m512i cipher_text =
                _mm512_xor_si512(sm4_ni_gather_raw_4x1(&loc_inp[4 * group], lane_mask[group]),
                                 keystream);

            chain[group] = _mm512_mask_blend_epi64(sm4_ni_lane_to_qword_mask(lane_mask[group]),
                                                   chain[group],
                                                   cipher_text);
            sm4_ni_scatter_raw_4x1(cipher_text, &loc_out[4 * group], lane_mask[group]);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                if (block < num_blocks[4 * group + lane]) {
                    loc_inp[4 * group + lane] += SM4_BLOCK_SIZE;
                    loc_out[4 * group + lane] += SM4_BLOCK_SIZE;
                }
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
    }

    zero_mb8((int64u(*)[8])round_keys, sizeof(round_keys) / sizeof(__m512i));
    zero_mb8((int64u(*)[8])chain, sizeof(chain) / sizeof(chain[0]));

    return status;
}

/*
// CBC-MAC: CBC encryption that keeps only the last ciphertext block as the tag.
//
// CCM calls this repeatedly, feeding the previous tag back in as the IV, so the tag has
// to be stored in the same plain byte order the IV is read from. Lines selected by
// mb_mask but holding no data are left untouched, matching the GFNI kernel.
*/
void sm4_ni_cbc_mac_kernel_mb16(__m128i pa_out[SM4_LINES],
                                const int8u* const pa_inp[SM4_LINES],
                                const int len[SM4_LINES],
                                const int32u* key_sched[SM4_ROUNDS],
                                __mmask16 mb_mask,
                                const int8u* pa_iv[SM4_LINES])
{
    __ALIGN64 __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 __m512i chain[SM4_NI_GROUPS];
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    int num_blocks[SM4_LINES];
    int max_blocks = 0;

    sm4_ni_repack_keys(round_keys, (const mbx_sm4_key_schedule*)key_sched, SM4_ENC);

    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        loc_inp[buf_no]    = pa_inp[buf_no];
        num_blocks[buf_no] = ((mb_mask >> buf_no) & 1) ? len[buf_no] / SM4_BLOCK_SIZE : 0;
        if (num_blocks[buf_no] > max_blocks)
            max_blocks = num_blocks[buf_no];
        /* a selected line with no data produces no tag */
        if (0 == num_blocks[buf_no])
            mb_mask &= (__mmask16) ~(1 << buf_no);
    }

    for (int group = 0; group < SM4_NI_GROUPS; group++)
        chain[group] =
            sm4_ni_gather_raw_4x1(&pa_iv[4 * group], sm4_ni_iv_lane_mask(num_blocks, group));

    for (int block = 0; block < max_blocks; block++) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];
        __mmask8 lane_mask[SM4_NI_GROUPS];

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            lane_mask[group] = 0;
            for (int lane = 0; lane < SM4_NI_LANES; lane++)
                if (block < num_blocks[4 * group + lane])
                    lane_mask[group] |= (__mmask8)(1 << lane);

            z[group] = _mm512_shuffle_epi8(
                _mm512_xor_si512(sm4_ni_gather_raw_4x1(&loc_inp[4 * group], lane_mask[group]),
                                 chain[group]),
                _mm512_load_si512(sm4_ni_shuf_in));
        }

        SM4_NI_ROUNDS_4(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            const __m512i cipher_text =
                _mm512_shuffle_epi8(z[group], _mm512_load_si512(sm4_ni_shuf_out));

            chain[group] = _mm512_mask_blend_epi64(sm4_ni_lane_to_qword_mask(lane_mask[group]),
                                                   chain[group],
                                                   cipher_text);

            for (int lane = 0; lane < SM4_NI_LANES; lane++)
                if (block < num_blocks[4 * group + lane])
                    loc_inp[4 * group + lane] += SM4_BLOCK_SIZE;
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
    }

    /* the tag is the final chain value */
    for (int group = 0; group < SM4_NI_GROUPS; group++) {
        const __mmask8 tag_mask = (__mmask8)((mb_mask >> (4 * group)) & 0xF);

        _mm_mask_storeu_epi64(&pa_out[4 * group + 0],
                              (__mmask8)(0x3 * ((tag_mask >> 0) & 1)),
                              _mm512_extracti64x2_epi64(chain[group], 0));
        _mm_mask_storeu_epi64(&pa_out[4 * group + 1],
                              (__mmask8)(0x3 * ((tag_mask >> 1) & 1)),
                              _mm512_extracti64x2_epi64(chain[group], 1));
        _mm_mask_storeu_epi64(&pa_out[4 * group + 2],
                              (__mmask8)(0x3 * ((tag_mask >> 2) & 1)),
                              _mm512_extracti64x2_epi64(chain[group], 2));
        _mm_mask_storeu_epi64(&pa_out[4 * group + 3],
                              (__mmask8)(0x3 * ((tag_mask >> 3) & 1)),
                              _mm512_extracti64x2_epi64(chain[group], 3));
    }

    zero_mb8((int64u(*)[8])round_keys, sizeof(round_keys) / sizeof(__m512i));
    zero_mb8((int64u(*)[8])chain, sizeof(chain) / sizeof(chain[0]));
}

/*
// CBC and CFB decryption both read the whole ciphertext up front, so unlike their
// encrypt directions they are fully parallel: every block can go through the cipher at
// once and the chaining is just an xor afterwards. They therefore use the same 4-slot
// bulk path as ECB (16 chains) and fall back to one block per line for the ragged tail.
//
//   CBC-dec:  plaintext[n] = D(cipher_text[n]) ^ cipher_text[n-1],  cipher_text[-1] = IV
//   CFB-dec:  plaintext[n] = E(cipher_text[n-1]) ^ cipher_text[n],  cipher_text[-1] = IV
//
// Both need the *previous* ciphertext block, which the output buffer may have already
// overwritten when out == input, so each block's ciphertext is kept before it is stored.
*/
#define SM4_NI_DEC_MODE_CBC (0)
#define SM4_NI_DEC_MODE_CFB (1)

static mbx_status16 sm4_ni_chained_dec_kernel_mb16(int8u* pa_out[SM4_LINES],
                                                   const int8u* pa_inp[SM4_LINES],
                                                   const int len[SM4_LINES],
                                                   const int32u* key_sched[SM4_ROUNDS],
                                                   __mmask16 mb_mask,
                                                   const int8u* pa_iv[SM4_LINES],
                                                   int mode)
{
    mbx_status16 status = 0;
    __ALIGN64 __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 __m512i chain[SM4_NI_GROUPS];
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];
    int num_blocks[SM4_LINES];
    int max_blocks = 0;
    int min_blocks = 0;

    /* CFB decryption runs the cipher forward over the previous ciphertext */
    sm4_ni_repack_keys(round_keys,
                       (const mbx_sm4_key_schedule*)key_sched,
                       (SM4_NI_DEC_MODE_CFB == mode) ? SM4_ENC : SM4_DEC);

    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        loc_inp[buf_no]    = pa_inp[buf_no];
        loc_out[buf_no]    = pa_out[buf_no];
        num_blocks[buf_no] = ((mb_mask >> buf_no) & 1) ? len[buf_no] / SM4_BLOCK_SIZE : 0;
        if (num_blocks[buf_no] > max_blocks)
            max_blocks = num_blocks[buf_no];
        if (0 == buf_no || num_blocks[buf_no] < min_blocks)
            min_blocks = num_blocks[buf_no];
    }

    for (int group = 0; group < SM4_NI_GROUPS; group++)
        chain[group] =
            sm4_ni_gather_raw_4x1(&pa_iv[4 * group], sm4_ni_iv_lane_mask(num_blocks, group));

    int block = 0;

    /* bulk path: SM4_NI_SLOTS blocks from every line, 16 chains in flight */
    for (; block + SM4_NI_SLOTS <= min_blocks; block += SM4_NI_SLOTS) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS][SM4_NI_SLOTS];
        __ALIGN64 __m512i cipher_text[SM4_NI_GROUPS][SM4_NI_SLOTS];

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            for (int slot = 0; slot < SM4_NI_SLOTS; slot++) {
                /* keep the ciphertext: out may alias input, and the xor below needs it */
                cipher_text[group][slot] = sm4_ni_gather_raw_4x1_at(&loc_inp[4 * group], slot);

                const __m512i prev = (0 == slot) ? chain[group] : cipher_text[group][slot - 1];
                /* CBC feeds the block itself to the cipher, CFB feeds the previous one */
                const __m512i in = (SM4_NI_DEC_MODE_CFB == mode) ? prev : cipher_text[group][slot];

                z[group][slot] = _mm512_shuffle_epi8(in, _mm512_load_si512(sm4_ni_shuf_in));
            }
        }

        SM4_NI_ROUNDS_16(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            for (int slot = 0; slot < SM4_NI_SLOTS; slot++) {
                const __m512i cipher =
                    _mm512_shuffle_epi8(z[group][slot], _mm512_load_si512(sm4_ni_shuf_out));
                const __m512i prev = (0 == slot) ? chain[group] : cipher_text[group][slot - 1];
                /* CBC xors the previous ciphertext, CFB xors this block's ciphertext */
                const __m512i mix = (SM4_NI_DEC_MODE_CFB == mode) ? cipher_text[group][slot] : prev;

                sm4_ni_scatter_raw_4x1_at(_mm512_xor_si512(cipher, mix), &loc_out[4 * group], slot);
            }

            chain[group] = cipher_text[group][SM4_NI_SLOTS - 1];

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                loc_inp[4 * group + lane] += SM4_NI_SLOTS * SM4_BLOCK_SIZE;
                loc_out[4 * group + lane] += SM4_NI_SLOTS * SM4_BLOCK_SIZE;
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(__m512i));
        zero_mb8((int64u(*)[8])cipher_text, sizeof(cipher_text) / sizeof(__m512i));
    }

    /* tail: one block per line, masking the lines that are already done */
    for (; block < max_blocks; block++) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];
        __ALIGN64 __m512i cipher_text[SM4_NI_GROUPS];
        __mmask8 lane_mask[SM4_NI_GROUPS];

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            lane_mask[group] = 0;
            for (int lane = 0; lane < SM4_NI_LANES; lane++)
                if (block < num_blocks[4 * group + lane])
                    lane_mask[group] |= (__mmask8)(1 << lane);

            cipher_text[group] = sm4_ni_gather_raw_4x1(&loc_inp[4 * group], lane_mask[group]);
            z[group]           = _mm512_shuffle_epi8((SM4_NI_DEC_MODE_CFB == mode) ? chain[group]
                                                                         : cipher_text[group],
                                           _mm512_load_si512(sm4_ni_shuf_in));
        }

        SM4_NI_ROUNDS_4(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            const __m512i cipher =
                _mm512_shuffle_epi8(z[group], _mm512_load_si512(sm4_ni_shuf_out));
            const __m512i mix = (SM4_NI_DEC_MODE_CFB == mode) ? cipher_text[group] : chain[group];

            sm4_ni_scatter_raw_4x1(_mm512_xor_si512(cipher, mix),
                                   &loc_out[4 * group],
                                   lane_mask[group]);

            /* a line that has run out keeps its chain value */
            chain[group] = _mm512_mask_blend_epi64(sm4_ni_lane_to_qword_mask(lane_mask[group]),
                                                   chain[group],
                                                   cipher_text[group]);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                if (block < num_blocks[4 * group + lane]) {
                    loc_inp[4 * group + lane] += SM4_BLOCK_SIZE;
                    loc_out[4 * group + lane] += SM4_BLOCK_SIZE;
                }
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
        zero_mb8((int64u(*)[8])cipher_text, sizeof(cipher_text) / sizeof(cipher_text[0]));
    }

    zero_mb8((int64u(*)[8])round_keys, sizeof(round_keys) / sizeof(__m512i));
    zero_mb8((int64u(*)[8])chain, sizeof(chain) / sizeof(chain[0]));

    return status;
}

mbx_status16 sm4_ni_cbc_dec_kernel_mb16(int8u* pa_out[SM4_LINES],
                                        const int8u* pa_inp[SM4_LINES],
                                        const int len[SM4_LINES],
                                        const int32u* key_sched[SM4_ROUNDS],
                                        __mmask16 mb_mask,
                                        const int8u* pa_iv[SM4_LINES])
{
    return sm4_ni_chained_dec_kernel_mb16(pa_out,
                                          pa_inp,
                                          len,
                                          key_sched,
                                          mb_mask,
                                          pa_iv,
                                          SM4_NI_DEC_MODE_CBC);
}

mbx_status16 sm4_ni_cfb128_dec_kernel_mb16(int8u* pa_out[SM4_LINES],
                                           const int8u* pa_inp[SM4_LINES],
                                           const int len[SM4_LINES],
                                           const int32u* key_sched[SM4_ROUNDS],
                                           const int8u* pa_iv[SM4_LINES],
                                           __mmask16 mb_mask)
{
    return sm4_ni_chained_dec_kernel_mb16(pa_out,
                                          pa_inp,
                                          len,
                                          key_sched,
                                          mb_mask,
                                          pa_iv,
                                          SM4_NI_DEC_MODE_CFB);
}

/*
// CTR and OFB are keystream generators: the message is only xored with the cipher output,
// so unlike the block modes they accept any length and the final block may be partial.
// The tail below therefore stores byte-granular, and a line's remaining byte count - not
// its block count - drives the mask.
//
// Each lane of a keystream register belongs to a different line, so a line's remaining
// length has to be turned into a per-lane byte mask one lane at a time.
*/
__MBX_INLINE void sm4_ni_xor_store_partial(__m512i keystream,
                                           const int8u* const input[SM4_NI_LANES],
                                           int8u* const out[SM4_NI_LANES],
                                           int slot,
                                           const int rem_bytes[SM4_NI_LANES])
{
    const int offset = slot * SM4_BLOCK_SIZE;
    /* the lane index is a loop variable, so the keystream goes through memory rather
       than through vextracti64x2, which needs a constant index */
    __ALIGN64 int8u ks[SM4_LINES * SM4_BLOCK_SIZE / 4];

    _mm512_store_si512(ks, keystream);

    for (int lane = 0; lane < SM4_NI_LANES; lane++) {
        const int rem = rem_bytes[lane] - offset;

        if (rem <= 0)
            continue;

        const __mmask16 byte_mask =
            (rem >= SM4_BLOCK_SIZE) ? (__mmask16)0xFFFF : (__mmask16)((1u << rem) - 1);
        const __m128i k  = _mm_load_si128((const __m128i*)&ks[lane * SM4_BLOCK_SIZE]);
        const __m128i pt = _mm_maskz_loadu_epi8(byte_mask, input[lane] + offset);

        _mm_mask_storeu_epi8(out[lane] + offset, byte_mask, _mm_xor_si128(k, pt));
    }

    zero_mb8((int64u(*)[8])ks, sizeof(ks) / sizeof(int64u) / 8);
}

/* GCM counter step: a 32-bit add on bytes 0..3 of each lane, wrapping there without
   carrying into the nonce, unlike the 128-bit increment SM4-CTR128 uses */
__MBX_INLINE __m512i sm4_ni_gcm_ctr_inc(__m512i ctr, int32u increment)
{
    return _mm512_mask_add_epi32(ctr, 0x1111, ctr, _mm512_set1_epi32((int)increment));
}

/* Load a group's 4 counters as numeric values; the caller holds them as byte strings */
__MBX_INLINE __m512i sm4_ni_ctr_load(int8u* const pa_ctr[4], __mmask8 lane_mask)
{
    return _mm512_shuffle_epi8(sm4_ni_gather_raw_4x1((const int8u* const*)pa_ctr, lane_mask),
                               _mm512_load_si512(sm4_ni_shuf_out));
}

mbx_status16 sm4_ni_ctr128_kernel_mb16(int8u* pa_out[SM4_LINES],
                                       const int8u* pa_inp[SM4_LINES],
                                       const int len[SM4_LINES],
                                       const int32u* key_sched[SM4_ROUNDS],
                                       __mmask16 mb_mask,
                                       int8u* pa_ctr[SM4_LINES])
{
    mbx_status16 status = 0;
    __ALIGN64 __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 __m512i ctr[SM4_NI_GROUPS];
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];
    int rem_bytes[SM4_LINES];
    int num_blocks[SM4_LINES];
    int max_blocks      = 0;
    int min_full_blocks = 0;

    sm4_ni_repack_keys(round_keys, (const mbx_sm4_key_schedule*)key_sched, SM4_ENC);

    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        const int active = ((mb_mask >> buf_no) & 1) && (len[buf_no] > 0);

        loc_inp[buf_no]   = pa_inp[buf_no];
        loc_out[buf_no]   = pa_out[buf_no];
        rem_bytes[buf_no] = active ? len[buf_no] : 0;
        /* a partial final block still needs a full cipher pass; rounded up this way rather
           than as (rem_bytes + SM4_BLOCK_SIZE - 1) so no length near INT_MAX overflows */
        num_blocks[buf_no] =
            rem_bytes[buf_no] / SM4_BLOCK_SIZE + (0 != rem_bytes[buf_no] % SM4_BLOCK_SIZE);
        if (num_blocks[buf_no] > max_blocks)
            max_blocks = num_blocks[buf_no];
        /* the bulk path stores whole blocks unmasked, so it must count only whole ones:
           a line of 49 bytes has 4 ceil-blocks but only 3 that may be stored in full */
        const int full_blocks = rem_bytes[buf_no] / SM4_BLOCK_SIZE;
        if (0 == buf_no || full_blocks < min_full_blocks)
            min_full_blocks = full_blocks;
    }

    for (int group = 0; group < SM4_NI_GROUPS; group++)
        ctr[group] = sm4_ni_ctr_load(&pa_ctr[4 * group], sm4_ni_iv_lane_mask(num_blocks, group));

    int block = 0;

    /* bulk path: 4 whole blocks from every line, 16 chains in flight */
    for (; block + SM4_NI_SLOTS <= min_full_blocks; block += SM4_NI_SLOTS) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS][SM4_NI_SLOTS];

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            for (int slot = 0; slot < SM4_NI_SLOTS; slot++)
                z[group][slot] = _mm512_shuffle_epi8(sm4_ni_ctr_inc(ctr[group], (int32u)slot),
                                                     _mm512_load_si512(sm4_ni_shuf_ctr_in));
        }

        SM4_NI_ROUNDS_16(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            for (int slot = 0; slot < SM4_NI_SLOTS; slot++) {
                const __m512i keystream =
                    _mm512_shuffle_epi8(z[group][slot], _mm512_load_si512(sm4_ni_shuf_out));

                sm4_ni_scatter_raw_4x1_at(
                    _mm512_xor_si512(keystream,
                                     sm4_ni_gather_raw_4x1_at(&loc_inp[4 * group], slot)),
                    &loc_out[4 * group],
                    slot);
            }

            ctr[group] = sm4_ni_ctr_inc(ctr[group], SM4_NI_SLOTS);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                loc_inp[4 * group + lane] += SM4_NI_SLOTS * SM4_BLOCK_SIZE;
                loc_out[4 * group + lane] += SM4_NI_SLOTS * SM4_BLOCK_SIZE;
                rem_bytes[4 * group + lane] -= SM4_NI_SLOTS * SM4_BLOCK_SIZE;
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(__m512i));
    }

    /* tail: one block per line, byte-granular so a partial final block is handled */
    for (; block < max_blocks; block++) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];

        for (int group = 0; group < SM4_NI_GROUPS; group++)
            z[group] = _mm512_shuffle_epi8(ctr[group], _mm512_load_si512(sm4_ni_shuf_ctr_in));

        SM4_NI_ROUNDS_4(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            const __m512i keystream =
                _mm512_shuffle_epi8(z[group], _mm512_load_si512(sm4_ni_shuf_out));

            sm4_ni_xor_store_partial(keystream,
                                     &loc_inp[4 * group],
                                     &loc_out[4 * group],
                                     0,
                                     &rem_bytes[4 * group]);

            ctr[group] = sm4_ni_ctr_inc(ctr[group], 1);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                if (rem_bytes[4 * group + lane] > 0) {
                    loc_inp[4 * group + lane] += SM4_BLOCK_SIZE;
                    loc_out[4 * group + lane] += SM4_BLOCK_SIZE;
                }
                rem_bytes[4 * group + lane] -= SM4_BLOCK_SIZE;
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
    }

    /* Write the counters back, advanced by the number of blocks consumed. Derived from the
       caller's original value rather than from the loop state, matching the GFNI kernel. */
    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        if (0 == num_blocks[buf_no])
            continue;

        const __m128i endian = _mm_load_si128((const __m128i*)sm4_ni_shuf_out);
        __m128i c = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)pa_ctr[buf_no]), endian);

        c = sm4_ni_ctr_inc128(c, (int32u)num_blocks[buf_no]);
        _mm_storeu_si128((__m128i*)pa_ctr[buf_no], _mm_shuffle_epi8(c, endian));
    }

    zero_mb8((int64u(*)[8])round_keys, sizeof(round_keys) / sizeof(__m512i));
    zero_mb8((int64u(*)[8])ctr, sizeof(ctr) / sizeof(ctr[0]));

    return status;
}

/*
// OFB. The keystream is a serial chain - ks[n] = E(ks[n-1]) - so unlike CTR it cannot run
// several blocks of a line at once and only SM4_NI_GROUPS chains are in flight.
//
// The IV is deliberately not written back: the GFNI kernel's writeback is unreachable
// (its mask is always zero by that point), so callers observe the IV unchanged and this
// kernel keeps that behaviour.
*/
mbx_status16 sm4_ni_ofb_kernel_mb16(int8u* pa_out[SM4_LINES],
                                    const int8u* pa_inp[SM4_LINES],
                                    const int len[SM4_LINES],
                                    const int32u* key_sched[SM4_ROUNDS],
                                    __mmask16 mb_mask,
                                    int8u* pa_iv[SM4_LINES])
{
    mbx_status16 status = 0;
    __ALIGN64 __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 __m512i chain[SM4_NI_GROUPS];
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];
    int rem_bytes[SM4_LINES];
    int num_blocks[SM4_LINES];
    int max_blocks = 0;

    sm4_ni_repack_keys(round_keys, (const mbx_sm4_key_schedule*)key_sched, SM4_ENC);

    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        const int active = ((mb_mask >> buf_no) & 1) && (len[buf_no] > 0);

        loc_inp[buf_no]   = pa_inp[buf_no];
        loc_out[buf_no]   = pa_out[buf_no];
        rem_bytes[buf_no] = active ? len[buf_no] : 0;
        num_blocks[buf_no] =
            rem_bytes[buf_no] / SM4_BLOCK_SIZE + (0 != rem_bytes[buf_no] % SM4_BLOCK_SIZE);
        if (num_blocks[buf_no] > max_blocks)
            max_blocks = num_blocks[buf_no];
    }

    for (int group = 0; group < SM4_NI_GROUPS; group++)
        chain[group] = sm4_ni_gather_raw_4x1((const int8u* const*)&pa_iv[4 * group],
                                             sm4_ni_iv_lane_mask(num_blocks, group));

    for (int block = 0; block < max_blocks; block++) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];

        for (int group = 0; group < SM4_NI_GROUPS; group++)
            z[group] = _mm512_shuffle_epi8(chain[group], _mm512_load_si512(sm4_ni_shuf_in));

        SM4_NI_ROUNDS_4(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            /* the keystream block feeds the next iteration */
            chain[group] = _mm512_shuffle_epi8(z[group], _mm512_load_si512(sm4_ni_shuf_out));

            sm4_ni_xor_store_partial(chain[group],
                                     &loc_inp[4 * group],
                                     &loc_out[4 * group],
                                     0,
                                     &rem_bytes[4 * group]);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                if (rem_bytes[4 * group + lane] > 0) {
                    loc_inp[4 * group + lane] += SM4_BLOCK_SIZE;
                    loc_out[4 * group + lane] += SM4_BLOCK_SIZE;
                }
                rem_bytes[4 * group + lane] -= SM4_BLOCK_SIZE;
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
    }

    zero_mb8((int64u(*)[8])round_keys, sizeof(round_keys) / sizeof(__m512i));
    zero_mb8((int64u(*)[8])chain, sizeof(chain) / sizeof(chain[0]));

    return status;
}

/*
// GCTR: the counter mode inside SM4-GCM.
//
// Same structure as sm4_ni_ctr128_kernel_mb16, with two differences that come from the GCM
// specification rather than from this code:
//   - the counter is a 32-bit field that wraps without carrying into the nonce;
//   - GCM keeps its per-line state in a 4x4-transposed order, so line i's counter lives at
//     pa_ctr[gcm_order[i]]. The order is an involution, and the caller has already applied
//     it to mb_mask, so undoing it there leaves mb_mask in natural line order - which is
//     what the input and output pointer arrays use.
//
// Takes the counter array rather than the GCM context so that this translation unit, the
// only one built with Intel® AVX10.2, needs no GCM headers.
*/
mbx_status16 sm4_ni_gctr_kernel_mb16(int8u* pa_out[SM4_LINES],
                                     const int8u* const pa_inp[SM4_LINES],
                                     const int len[SM4_LINES],
                                     const int32u* key_sched[SM4_ROUNDS],
                                     __mmask16 mb_mask,
                                     __m128i pa_ctr[SM4_LINES],
                                     const int gcm_order[SM4_LINES])
{
    mbx_status16 status = 0;
    __ALIGN64 __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 __m512i ctr[SM4_NI_GROUPS];
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];
    int rem_bytes[SM4_LINES];
    int num_blocks[SM4_LINES];
    int max_blocks      = 0;
    int min_full_blocks = 0;

    sm4_ni_repack_keys(round_keys, (const mbx_sm4_key_schedule*)key_sched, SM4_ENC);

    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        const int active = ((mb_mask >> buf_no) & 1) && (len[buf_no] > 0);

        loc_inp[buf_no]   = pa_inp[buf_no];
        loc_out[buf_no]   = pa_out[buf_no];
        rem_bytes[buf_no] = active ? len[buf_no] : 0;
        num_blocks[buf_no] =
            rem_bytes[buf_no] / SM4_BLOCK_SIZE + (0 != rem_bytes[buf_no] % SM4_BLOCK_SIZE);
        if (num_blocks[buf_no] > max_blocks)
            max_blocks = num_blocks[buf_no];

        const int full_blocks = rem_bytes[buf_no] / SM4_BLOCK_SIZE;
        if (0 == buf_no || full_blocks < min_full_blocks)
            min_full_blocks = full_blocks;
    }

    /* gather each group's counters out of the GCM ordering */
    for (int group = 0; group < SM4_NI_GROUPS; group++) {
        __ALIGN64 int8u packed[sizeof(__m512i)];

        _mm512_store_si512(packed, _mm512_setzero_si512());
        for (int lane = 0; lane < SM4_NI_LANES; lane++) {
            const int buf_no = 4 * group + lane;

            if (num_blocks[buf_no] > 0)
                _mm_store_si128((__m128i*)&packed[lane * SM4_BLOCK_SIZE],
                                pa_ctr[gcm_order[buf_no]]);
        }
        ctr[group] = _mm512_load_si512(packed);
        zero_mb8((int64u(*)[8])packed, sizeof(packed) / sizeof(int64u) / 8);
    }

    int block = 0;

    /* bulk path: 4 whole blocks from every line, 16 chains in flight */
    for (; block + SM4_NI_SLOTS <= min_full_blocks; block += SM4_NI_SLOTS) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS][SM4_NI_SLOTS];

        for (int group = 0; group < SM4_NI_GROUPS; group++)
            for (int slot = 0; slot < SM4_NI_SLOTS; slot++)
                /* block n of a line uses the stored counter + n, so the first is +0 */
                z[group][slot] = _mm512_shuffle_epi8(sm4_ni_gcm_ctr_inc(ctr[group], (int32u)slot),
                                                     _mm512_load_si512(sm4_ni_shuf_ctr_in));

        SM4_NI_ROUNDS_16(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            for (int slot = 0; slot < SM4_NI_SLOTS; slot++) {
                const __m512i keystream =
                    _mm512_shuffle_epi8(z[group][slot], _mm512_load_si512(sm4_ni_shuf_out));

                sm4_ni_scatter_raw_4x1_at(
                    _mm512_xor_si512(keystream,
                                     sm4_ni_gather_raw_4x1_at(&loc_inp[4 * group], slot)),
                    &loc_out[4 * group],
                    slot);
            }

            ctr[group] = sm4_ni_gcm_ctr_inc(ctr[group], SM4_NI_SLOTS);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                loc_inp[4 * group + lane] += SM4_NI_SLOTS * SM4_BLOCK_SIZE;
                loc_out[4 * group + lane] += SM4_NI_SLOTS * SM4_BLOCK_SIZE;
                rem_bytes[4 * group + lane] -= SM4_NI_SLOTS * SM4_BLOCK_SIZE;
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(__m512i));
    }

    /* tail: one block per line, byte-granular for a partial final block */
    for (; block < max_blocks; block++) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];

        for (int group = 0; group < SM4_NI_GROUPS; group++)
            z[group] = _mm512_shuffle_epi8(ctr[group], _mm512_load_si512(sm4_ni_shuf_ctr_in));

        SM4_NI_ROUNDS_4(z, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            const __m512i keystream =
                _mm512_shuffle_epi8(z[group], _mm512_load_si512(sm4_ni_shuf_out));

            sm4_ni_xor_store_partial(keystream,
                                     &loc_inp[4 * group],
                                     &loc_out[4 * group],
                                     0,
                                     &rem_bytes[4 * group]);

            ctr[group] = sm4_ni_gcm_ctr_inc(ctr[group], 1);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                if (rem_bytes[4 * group + lane] > 0) {
                    loc_inp[4 * group + lane] += SM4_BLOCK_SIZE;
                    loc_out[4 * group + lane] += SM4_BLOCK_SIZE;
                }
                rem_bytes[4 * group + lane] -= SM4_BLOCK_SIZE;
            }
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
    }

    /* advance the stored counters by the number of blocks consumed, back into GCM order */
    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        if (0 == num_blocks[buf_no])
            continue;

        pa_ctr[gcm_order[buf_no]] =
            _mm_add_epi32(pa_ctr[gcm_order[buf_no]], _mm_maskz_loadu_epi32(1, &num_blocks[buf_no]));
    }

    zero_mb8((int64u(*)[8])round_keys, sizeof(round_keys) / sizeof(__m512i));
    zero_mb8((int64u(*)[8])ctr, sizeof(ctr) / sizeof(ctr[0]));

    return status;
}

/*
// SM4-XTS.
//
// Each block is xored with its tweak, run through the cipher, then xored with the tweak
// again; the tweak advances by one GF(2^128) multiplication per block. The initial tweak
// is encrypted with the second key schedule, always in the forward direction even when the
// data is being decrypted.
//
// A trailing partial block uses ciphertext stealing, which processes the last two blocks
// out of order. Only the very last full block is affected, so the bulk loop below stops
// early enough to leave at least one full block plus the partial one to the tail, and the
// tail handles the swap. Decryption also exchanges the last two tweaks, because the
// stolen block belongs to the earlier tweak.
*/
static void sm4_ni_xts_encrypt_tweaks(__m512i tweak[SM4_NI_GROUPS],
                                      const int8u* pa_tweak[SM4_LINES],
                                      const int32u* key_sched2[SM4_ROUNDS],
                                      const int num_blocks[SM4_LINES])
{
    __ALIGN64 __m512i tweak_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 __m512i z[SM4_NI_GROUPS];

    sm4_ni_repack_keys(tweak_keys, (const mbx_sm4_key_schedule*)key_sched2, SM4_ENC);

    for (int group = 0; group < SM4_NI_GROUPS; group++)
        z[group] = sm4_ni_gather_4x1(&pa_tweak[4 * group], sm4_ni_iv_lane_mask(num_blocks, group));

    SM4_NI_ROUNDS_4(z, tweak_keys);

    for (int group = 0; group < SM4_NI_GROUPS; group++)
        tweak[group] = _mm512_shuffle_epi8(z[group], _mm512_load_si512(sm4_ni_shuf_out));

    zero_mb8((int64u(*)[8])tweak_keys, sizeof(tweak_keys) / sizeof(__m512i));
    zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
}

__MBX_INLINE int sm4_ni_xts_has_partial(const int partial[SM4_LINES])
{
    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++)
        if (partial[buf_no])
            return 1;

    return 0;
}

/* Gather one group's worth of saved per-line tweaks back into a zmm */
__MBX_INLINE __m512i sm4_ni_xts_pack_tweaks(const int8u saved[SM4_LINES][SM4_BLOCK_SIZE], int group)
{
    __m512i z = _mm512_castsi128_si512(_mm_load_si128((const __m128i*)saved[4 * group + 0]));

    z = _mm512_inserti64x2(z, _mm_load_si128((const __m128i*)saved[4 * group + 1]), 1);
    z = _mm512_inserti64x2(z, _mm_load_si128((const __m128i*)saved[4 * group + 2]), 2);
    z = _mm512_inserti64x2(z, _mm_load_si128((const __m128i*)saved[4 * group + 3]), 3);

    return z;
}

/* Build the stolen block for each lane: the partial input bytes, completed to a full block
   with the trailing bytes of the already-processed last full block */
__MBX_INLINE __m512i sm4_ni_xts_build_stolen(const int8u* const input[SM4_NI_LANES],
                                             const int8u full_out[SM4_LINES][SM4_BLOCK_SIZE],
                                             int group,
                                             const int partial[SM4_LINES])
{
    __ALIGN64 int8u block[sizeof(__m512i)];

    _mm512_store_si512(block, _mm512_setzero_si512());

    for (int lane = 0; lane < SM4_NI_LANES; lane++) {
        const int buf_no = 4 * group + lane;
        const int rem    = partial[buf_no];

        if (0 == rem)
            continue;

        const __mmask16 rem_mask = (__mmask16)((1u << rem) - 1);
        /* the partial bytes sit just past the held-back full block */
        const __m128i tail = _mm_maskz_loadu_epi8(rem_mask, input[lane] + SM4_BLOCK_SIZE);
        const __m128i keep =
            _mm_mask_load_epi64(_mm_setzero_si128(), 0x3, (const void*)full_out[buf_no]);

        _mm_store_si128((__m128i*)&block[lane * SM4_BLOCK_SIZE],
                        _mm_mask_blend_epi8(rem_mask, keep, tail));
    }

    const __m512i z = _mm512_load_si512(block);

    zero_mb8((int64u(*)[8])block, sizeof(block) / sizeof(int64u) / 8);

    return z;
}

/* One tweaked block per line: in ^ tweak -> cipher -> ^ tweak */
__MBX_INLINE void sm4_ni_xts_one_pass(__m512i z[SM4_NI_GROUPS],
                                      const __m512i tweak[SM4_NI_GROUPS],
                                      const __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS])
{
    for (int group = 0; group < SM4_NI_GROUPS; group++)
        z[group] = _mm512_shuffle_epi8(_mm512_xor_si512(z[group], tweak[group]),
                                       _mm512_load_si512(sm4_ni_shuf_in));

    SM4_NI_ROUNDS_4(z, round_keys);

    for (int group = 0; group < SM4_NI_GROUPS; group++)
        z[group] =
            _mm512_xor_si512(_mm512_shuffle_epi8(z[group], _mm512_load_si512(sm4_ni_shuf_out)),
                             tweak[group]);
}

mbx_status16 sm4_ni_xts_kernel_mb16(int8u* pa_out[SM4_LINES],
                                    const int8u* pa_inp[SM4_LINES],
                                    const int len[SM4_LINES],
                                    const int32u* key_sched1[SM4_ROUNDS],
                                    const int32u* key_sched2[SM4_ROUNDS],
                                    const int8u* pa_tweak[SM4_LINES],
                                    __mmask16 mb_mask,
                                    const int operation)
{
    mbx_status16 status = 0;
    __ALIGN64 __m512i round_keys[SM4_NI_GROUPS][SM4_NI_KEY_STEPS];
    __ALIGN64 __m512i tweak[SM4_NI_GROUPS];
    __ALIGN64 const int8u* loc_inp[SM4_LINES];
    __ALIGN64 int8u* loc_out[SM4_LINES];
    int num_blocks[SM4_LINES]; /* whole blocks, excluding any partial tail */
    int partial[SM4_LINES];    /* bytes in the trailing partial block, 0 if none */
    int max_blocks = 0;

    sm4_ni_repack_keys(round_keys, (const mbx_sm4_key_schedule*)key_sched1, operation);

    for (int buf_no = 0; buf_no < SM4_LINES; buf_no++) {
        const int active  = ((mb_mask >> buf_no) & 1) && (len[buf_no] >= SM4_BLOCK_SIZE);
        const int loc_len = active ? len[buf_no] : 0;

        loc_inp[buf_no]    = pa_inp[buf_no];
        loc_out[buf_no]    = pa_out[buf_no];
        num_blocks[buf_no] = loc_len / SM4_BLOCK_SIZE;
        partial[buf_no]    = loc_len & (SM4_BLOCK_SIZE - 1);
        if (num_blocks[buf_no] > max_blocks)
            max_blocks = num_blocks[buf_no];
    }

    sm4_ni_xts_encrypt_tweaks(tweak, pa_tweak, key_sched2, num_blocks);

    /*
     * All lines advance their tweak in lockstep, so at iteration block a lane's tweak is
     * exactly the one block block of that line needs. Lines with a partial tail hold back
     * their last full block, and the two tweaks the stealing step needs are captured as
     * they go past.
     */
    __ALIGN64 int8u tweak_last[SM4_LINES][SM4_BLOCK_SIZE];  /* T of the last full block */
    __ALIGN64 int8u tweak_steal[SM4_LINES][SM4_BLOCK_SIZE]; /* T one past it */
    const int has_partial = sm4_ni_xts_has_partial(partial);

    /*
     * Only lines with a partial tail write these, but sm4_ni_xts_pack_tweaks() reads a whole
     * group at a time, so clear them up front to keep the untouched lanes determinate. They
     * are masked out of the store either way; this just avoids an indeterminate read.
     */
    if (has_partial) {
        for (int buf_no = 0; buf_no < SM4_LINES; buf_no += 4) {
            _mm512_storeu_si512(&tweak_last[buf_no], _mm512_setzero_si512());
            _mm512_storeu_si512(&tweak_steal[buf_no], _mm512_setzero_si512());
        }
    }

    for (int block = 0; block < max_blocks; block++) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];
        __mmask8 lane_mask[SM4_NI_GROUPS];

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            lane_mask[group] = 0;
            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                const int buf_no = 4 * group + lane;

                if (block >= num_blocks[buf_no])
                    continue;
                /* hold back the final full block: stealing rewrites it */
                if (partial[buf_no] && block == num_blocks[buf_no] - 1)
                    continue;

                lane_mask[group] |= (__mmask8)(1 << lane);
            }

            z[group] = sm4_ni_gather_raw_4x1(&loc_inp[4 * group], lane_mask[group]);
        }

        sm4_ni_xts_one_pass(z, tweak, round_keys);

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            __ALIGN64 int8u cur_tweak[sizeof(__m512i)];

            sm4_ni_scatter_raw_4x1(z[group], &loc_out[4 * group], lane_mask[group]);
            _mm512_store_si512(cur_tweak, tweak[group]);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                const int buf_no = 4 * group + lane;

                /* capture the tweak of this line's last full block as it comes up */
                if (partial[buf_no] && block == num_blocks[buf_no] - 1)
                    _mm_store_si128(
                        (__m128i*)tweak_last[buf_no],
                        _mm_load_si128((const __m128i*)&cur_tweak[lane * SM4_BLOCK_SIZE]));

                /* only advance where a block was actually processed: a held-back block must
                   leave the pointers on it, so the stealing step can find it */
                if ((lane_mask[group] >> lane) & 1) {
                    loc_inp[buf_no] += SM4_BLOCK_SIZE;
                    loc_out[buf_no] += SM4_BLOCK_SIZE;
                }
            }

            tweak[group] = sm4_ni_tweak_mul(tweak[group]);
            _mm512_store_si512(cur_tweak, tweak[group]);

            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                const int buf_no = 4 * group + lane;

                if (partial[buf_no] && block == num_blocks[buf_no] - 1)
                    _mm_store_si128(
                        (__m128i*)tweak_steal[buf_no],
                        _mm_load_si128((const __m128i*)&cur_tweak[lane * SM4_BLOCK_SIZE]));
            }

            zero_mb8((int64u(*)[8])cur_tweak, sizeof(cur_tweak) / sizeof(int64u) / 8);
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
    }

    /*
     * Ciphertext stealing for the lines that end on a partial block. The last full block
     * and the partial one are processed together: the full block is enciphered, its leading
     * bytes become the partial output, and its trailing bytes are borrowed to complete the
     * partial input into a whole block.
     *
     * Encryption enciphers the full block under its own tweak and the completed block under
     * the next one; decryption uses them the other way round, because the stolen bytes
     * belong to the earlier tweak.
     */
    if (has_partial) {
        __ALIGN64 __m512i z[SM4_NI_GROUPS];
        __ALIGN64 __m512i packed_full[SM4_NI_GROUPS];
        __ALIGN64 __m512i packed_steal[SM4_NI_GROUPS];
        __mmask8 lane_mask[SM4_NI_GROUPS];

        /* pass 1: the held-back full block */
        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            lane_mask[group] = 0;
            for (int lane = 0; lane < SM4_NI_LANES; lane++)
                if (partial[4 * group + lane])
                    lane_mask[group] |= (__mmask8)(1 << lane);

            packed_full[group]  = sm4_ni_xts_pack_tweaks(tweak_last, group);
            packed_steal[group] = sm4_ni_xts_pack_tweaks(tweak_steal, group);
            z[group]            = sm4_ni_gather_raw_4x1(&loc_inp[4 * group], lane_mask[group]);
        }

        /* decryption swaps the two tweaks */
        sm4_ni_xts_one_pass(z, (SM4_ENC == operation) ? packed_full : packed_steal, round_keys);

        /* pass 2: complete the partial block from the result and re-encipher */
        __ALIGN64 int8u full_out[SM4_LINES][SM4_BLOCK_SIZE];

        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            __ALIGN64 int8u tmp[sizeof(__m512i)];

            _mm512_store_si512(tmp, z[group]);
            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                const int buf_no = 4 * group + lane;

                if (partial[buf_no])
                    _mm_store_si128((__m128i*)full_out[buf_no],
                                    _mm_load_si128((const __m128i*)&tmp[lane * SM4_BLOCK_SIZE]));
            }
            zero_mb8((int64u(*)[8])tmp, sizeof(tmp) / sizeof(int64u) / 8);
        }

        for (int group = 0; group < SM4_NI_GROUPS; group++)
            z[group] = sm4_ni_xts_build_stolen(&loc_inp[4 * group], full_out, group, partial);

        sm4_ni_xts_one_pass(z, (SM4_ENC == operation) ? packed_steal : packed_full, round_keys);

        /* store: the completed block at the last full position, the leading bytes after it */
        for (int group = 0; group < SM4_NI_GROUPS; group++) {
            __ALIGN64 int8u tmp[sizeof(__m512i)];

            _mm512_store_si512(tmp, z[group]);
            for (int lane = 0; lane < SM4_NI_LANES; lane++) {
                const int buf_no = 4 * group + lane;
                const int rem    = partial[buf_no];

                if (0 == rem)
                    continue;

                const __mmask16 rem_mask = (__mmask16)((1u << rem) - 1);

                _mm_storeu_si128((__m128i*)loc_out[buf_no],
                                 _mm_load_si128((const __m128i*)&tmp[lane * SM4_BLOCK_SIZE]));
                _mm_mask_storeu_epi8(loc_out[buf_no] + SM4_BLOCK_SIZE,
                                     rem_mask,
                                     _mm_load_si128((const __m128i*)full_out[buf_no]));
            }
            zero_mb8((int64u(*)[8])tmp, sizeof(tmp) / sizeof(int64u) / 8);
        }

        zero_mb8((int64u(*)[8])z, sizeof(z) / sizeof(z[0]));
        zero_mb8((int64u(*)[8])packed_full, sizeof(packed_full) / sizeof(packed_full[0]));
        zero_mb8((int64u(*)[8])packed_steal, sizeof(packed_steal) / sizeof(packed_steal[0]));
        zero_mb8((int64u(*)[8])full_out, sizeof(full_out) / sizeof(int64u) / 8);
    }

    zero_mb8((int64u(*)[8])round_keys, sizeof(round_keys) / sizeof(__m512i));
    zero_mb8((int64u(*)[8])tweak, sizeof(tweak) / sizeof(tweak[0]));
    zero_mb8((int64u(*)[8])tweak_last, sizeof(tweak_last) / sizeof(int64u) / 8);
    zero_mb8((int64u(*)[8])tweak_steal, sizeof(tweak_steal) / sizeof(int64u) / 8);

    return status;
}

#endif /* #if (_MBX >= _MBX_K1) && defined(MBX_SM4NI_ENABLED) */
