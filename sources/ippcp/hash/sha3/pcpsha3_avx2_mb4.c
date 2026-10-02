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
//
//  Purpose:
//     Cryptography Primitive.
//     4-way multi-buffer SHAKE128/SHAKE256 optimized with AVX2 (L9).
//
//     L9 runs the Keccak permutation one lane at a time (scalar cp_keccak_kernel).
//     This runs 4 independent sponges in one 256-bit SIMD pass, which fills the
//     vector width a single scalar lane leaves idle. Each lane matches the scalar
//     SHAKE stream byte-for-byte, so callers (ML-DSA, ML-KEM sampling) reuse the
//     same MB4 API and stay KAT-exact.
//
//     AVX2 has no vector 64-bit rotate (vprolq) or 3-input logic (vpternlogq), so:
//       rotate -> (x<<r) | (x>>(64-r))   [vpsllq | vpsrlq | vpor]
//       chi    -> a ^ (~b & c)           [vpandn | vpxor]
//
//     The permutation is fused and register-resident: all 25 state words stay in named
//     ymm registers across all 24 rounds, and rho+pi are applied by choosing WHICH
//     register each result is written to instead of by moving data. Rounds are grouped
//     4 at a time, after which the naming realigns to the natural order, so nothing
//     spills to memory between groups. Rotate-by-8 and rotate-by-56 use a byte permute
//     (vpshufb) rather than the shift|shift|or triple, keeping those two rho offsets off
//     the shift ports.
//
//     This fused round structure is the standard one, used by the Keccak Team's own AVX2
//     code (XKCP KeccakP-1600-times4, public domain / CC0) and by other AVX2 Keccak
//     implementations. It is written here independently in intrinsics; no third-party
//     code is included. Cross-checked bit-identical against both XKCP times4 and the
//     scalar SHAKE stream.
//
//  Contents:
//     cp_SHA3_SHAKE128_InitMB4()     cp_SHA3_SHAKE256_InitMB4()
//     cp_SHA3_SHAKE128_AbsorbMB4()   cp_SHA3_SHAKE256_AbsorbMB4()
//     cp_SHA3_SHAKE128_FinalizeMB4() cp_SHA3_SHAKE256_FinalizeMB4()
//     cp_SHA3_SHAKE128_SqueezeMB4()  cp_SHA3_SHAKE256_SqueezeMB4()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcptool.h"
#include "hash/sha3/sha3_stuff.h"

#if (_IPP32E == _IPP32E_L9)

#include <immintrin.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

/* Layout of the caller-owned state.ctx buffer (Ipp8u[STATE_x4_SIZE]). state[] is
   accessed as a plain __m256i lvalue, so the compiler may use aligned moves
   (vmovdqa) for it; the callers declare the backing store as a plain Ipp8u array
   with no alignment attribute, and a misaligned one would fault. The struct is
   therefore placed at the first 32-byte boundary inside the buffer (see ctx_of)
   rather than at its start, which keeps the guarantee inside this file instead of
   relying on every caller to align its array. */
typedef struct {
    __m256i state[25];             /* 25 Keccak words, 4 lanes (64-bit) each */
    Ipp8u block[4][SHAKE128_RATE]; /* per-lane current squeezed block (secret)  */
    Ipp32s rate;                   /* 168 (SHAKE128) or 136 (SHAKE256)          */
    Ipp32s bufPos;                 /* consumed bytes of the current block (0..rate) */
    Ipp32s absLen;                 /* bytes stashed by absorb, padded by finalize   */
} shake_ctx_x4;

#define SHAKE_X4_CTX_ALIGNMENT 32

/* The ctx plus the worst-case align-up skew must fit in the caller-owned
   Ipp8u[STATE_x4_SIZE] buffer (C99 build, so this is a negative-size-array compile
   check rather than _Static_assert). */
typedef char shake_ctx_x4_fits_in_state
    [((sizeof(shake_ctx_x4) + SHAKE_X4_CTX_ALIGNMENT - 1) <= STATE_x4_SIZE) ? 1 : -1];

/* First 32-byte-aligned address inside the caller's buffer. Deterministic, so every
   entry point derives the same ctx pointer from the same buffer. */
static shake_ctx_x4* ctx_of(Ipp8u* buffer)
{
    return (shake_ctx_x4*)(IPP_ALIGNED_PTR(buffer, SHAKE_X4_CTX_ALIGNMENT));
}

/* AVX2 has no vector rotate: (x<<r)|(x>>(64-r)). r is a compile-time constant. */
#define ROL(x, r) _mm256_or_si256(_mm256_slli_epi64((x), (r)), _mm256_srli_epi64((x), 64 - (r)))
/* chi term: ~b & c */
#define ANDN(b, c) _mm256_andnot_si256((b), (c))
#define XOR(a, b)  _mm256_xor_si256((a), (b))
/* a ^ (~b & c): one chi output word. */
#define CHI(a, b, c) XOR((a), ANDN((b), (c)))
/* Parity of one state column (5 words). */
#define XOR5(a, b, c, d, e) XOR(XOR(XOR((a), (b)), XOR((c), (d))), (e))

/* Rotate left by 8 and by 56 as a single in-lane byte permute. vpshufb issues on the
   shuffle port, so these two rho offsets stop competing with vpsllq/vpsrlq. Each byte
   index selects within its own 128-bit half, hence the two mirrored halves.

   How the index constants below were built. A rotate by a whole number of bytes is just a
   byte permutation, so for a rotate left by r bytes, output byte j of a 64-bit lane takes
   source byte (j - r) mod 8:
     ROL_8  is rotate left 8 bits  = 1 byte  -> src = (j - 1) mod 8
     ROL_56 is rotate left 56 bits = right 8 = -1 byte -> src = (j + 1) mod 8
   Each of the four 64-bit lanes adds its own base offset (0, 8, 16, 24) because vpshufb
   indexes within its own 128-bit half. _mm256_set_epi64x takes lanes most-significant
   first, so the four words below read lane3, lane2, lane1, lane0. Example, ROL_8 lane0:
   j=0 takes src 7, j=1 takes src 0, j=2 takes src 1, ... giving bytes 07 00 01 02 03 04
   05 06, which little-endian packs to 0x0605040302010007. */
#define ROL_8(x)                                                            \
    _mm256_shuffle_epi8((x),                                                \
                        _mm256_set_epi64x((long long)0x1e1d1c1b1a19181fULL, \
                                          (long long)0x1615141312111017ULL, \
                                          (long long)0x0e0d0c0b0a09080fULL, \
                                          (long long)0x0605040302010007ULL))
#define ROL_56(x)                                                           \
    _mm256_shuffle_epi8((x),                                                \
                        _mm256_set_epi64x((long long)0x181f1e1d1c1b1a19ULL, \
                                          (long long)0x1017161514131211ULL, \
                                          (long long)0x080f0e0d0c0b0a09ULL, \
                                          (long long)0x0007060504030201ULL))
/* Rho rotation by a compile-time offset, picking the cheapest form for each offset. */
#define ROL_RHO(x, r) ((r) == 0 ? (x) : (r) == 8 ? ROL_8(x) : (r) == 56 ? ROL_56(x) : ROL((x), (r)))

/* Keccak-f[1600] iota round constants, one per round, as defined by FIPS 202 Algorithm 5
   (Keccak-p permutation, step iota). They are not arbitrary: RC[round] has bit (2^j - 1)
   set for j = 0..6 exactly when the FIPS 202 rc(j + 7*round) LFSR bit is 1, where rc() is
   the 8-bit LFSR of Algorithm 5 (taps at positions 0, 4, 5, 6). Only the 7 bit positions
   0, 1, 3, 7, 15, 31, 63 can ever be set, which is why every value below is built from
   0x...0001 / 8082 / 808a style patterns. These are the same constants used by every
   Keccak implementation; all 24 were regenerated from the LFSR and checked against this
   table. */
__ALIGN32 static const Ipp64u KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Theta, first half: the 5 column parities, then the 5 correction words applied below.
   thetaD[x] = parity[x-1] ^ ROL(parity[x+1], 1), indices mod 5. */
#define THETA_PREPARE()                                           \
    columnParity0 = XOR5(word00, word10, word20, word30, word40); \
    columnParity1 = XOR5(word01, word11, word21, word31, word41); \
    columnParity2 = XOR5(word02, word12, word22, word32, word42); \
    columnParity3 = XOR5(word03, word13, word23, word33, word43); \
    columnParity4 = XOR5(word04, word14, word24, word34, word44); \
    thetaD0       = XOR(columnParity4, ROL(columnParity1, 1));    \
    thetaD1       = XOR(columnParity0, ROL(columnParity2, 1));    \
    thetaD2       = XOR(columnParity1, ROL(columnParity3, 1));    \
    thetaD3       = XOR(columnParity2, ROL(columnParity4, 1));    \
    thetaD4       = XOR(columnParity3, ROL(columnParity0, 1))

/* clang-format off */
/* The row macros below are kept hand-aligned: clang-format would put each of ROW_STEP's
   15 arguments on its own line, hiding the rho-offset / chi-rotation table that makes
   them checkable against FIPS 202. */

/* One output row: finish theta on the 5 source words, rho-rotate them, and write them
   into a ROTATED subset of the fixed chi-input set chiIn0..chiIn4 - that rotation IS pi,
   so no data is moved to permute lanes. Chi then always reads chiIn0..chiIn4 in natural
   order and its 5 results overwrite the 5 source words in place.
   Source words and chi inputs never alias: the chi inputs were filled by the PREVIOUS
   row's rho step, so reading them here is reading the previous row's output. */
#define ROW_STEP(src0, src1, src2, src3, src4,       \
                 rho0, rho1, rho2, rho3, rho4,       \
                 dst0, dst1, dst2, dst3, dst4)       \
    (dst0) = ROL_RHO(XOR((src0), thetaD0), (rho0)); \
    (dst1) = ROL_RHO(XOR((src1), thetaD1), (rho1)); \
    (dst2) = ROL_RHO(XOR((src2), thetaD2), (rho2)); \
    (dst3) = ROL_RHO(XOR((src3), thetaD3), (rho3)); \
    (dst4) = ROL_RHO(XOR((src4), thetaD4), (rho4)); \
    (src0) = CHI(chiIn0, chiIn1, chiIn2);           \
    (src1) = CHI(chiIn1, chiIn2, chiIn3);           \
    (src2) = CHI(chiIn2, chiIn3, chiIn4);           \
    (src3) = CHI(chiIn3, chiIn4, chiIn0);           \
    (src4) = CHI(chiIn4, chiIn0, chiIn1)

/* The 5 rows of a round differ only in their rho offsets and in how far the chi-input set
   is rotated (pi). Both are fixed per row position, so bind them once here; only the
   state words vary from round to round. */
#define ROW_STEP_0(src0, src1, src2, src3, src4)     \
    ROW_STEP(src0, src1, src2, src3, src4,           \
              0,  44,  43,  21,  14,                 \
             chiIn0, chiIn1, chiIn2, chiIn3, chiIn4)
#define ROW_STEP_1(src0, src1, src2, src3, src4)     \
    ROW_STEP(src0, src1, src2, src3, src4,           \
              3,  45,  61,  28,  20,                 \
             chiIn2, chiIn3, chiIn4, chiIn0, chiIn1)
#define ROW_STEP_2(src0, src1, src2, src3, src4)     \
    ROW_STEP(src0, src1, src2, src3, src4,           \
             18,   1,   6,  25,   8,                 \
             chiIn4, chiIn0, chiIn1, chiIn2, chiIn3)
#define ROW_STEP_3(src0, src1, src2, src3, src4)     \
    ROW_STEP(src0, src1, src2, src3, src4,           \
             36,  10,  15,  56,  27,                 \
             chiIn1, chiIn2, chiIn3, chiIn4, chiIn0)
#define ROW_STEP_4(src0, src1, src2, src3, src4)     \
    ROW_STEP(src0, src1, src2, src3, src4,           \
             41,   2,  62,  55,  39,                 \
             chiIn3, chiIn4, chiIn0, chiIn1, chiIn2)
/* clang-format on */

/* Iota: add the round constant to the (0,0) word. */
#define IOTA(word, roundConst) (word) = XOR((word), _mm256_set1_epi64x((long long)(roundConst)))

/* Four rounds. Because pi is expressed as register naming, the words a given row consumes
   move from round to round; those groupings are what the varying argument lists below
   encode. After exactly 4 rounds the naming is back to word00..word44, so consecutive
   groups chain with no store/reload. */
#define FOUR_ROUNDS(firstRound)                         \
    THETA_PREPARE();                                    \
    ROW_STEP_0(word00, word11, word22, word33, word44); \
    IOTA(word00, KECCAK_RC[(firstRound) + 0]);          \
    ROW_STEP_1(word20, word31, word42, word03, word14); \
    ROW_STEP_2(word40, word01, word12, word23, word34); \
    ROW_STEP_3(word10, word21, word32, word43, word04); \
    ROW_STEP_4(word30, word41, word02, word13, word24); \
                                                        \
    THETA_PREPARE();                                    \
    ROW_STEP_0(word00, word31, word12, word43, word24); \
    IOTA(word00, KECCAK_RC[(firstRound) + 1]);          \
    ROW_STEP_1(word40, word21, word02, word33, word14); \
    ROW_STEP_2(word30, word11, word42, word23, word04); \
    ROW_STEP_3(word20, word01, word32, word13, word44); \
    ROW_STEP_4(word10, word41, word22, word03, word34); \
                                                        \
    THETA_PREPARE();                                    \
    ROW_STEP_0(word00, word21, word42, word13, word34); \
    IOTA(word00, KECCAK_RC[(firstRound) + 2]);          \
    ROW_STEP_1(word30, word01, word22, word43, word14); \
    ROW_STEP_2(word10, word31, word02, word23, word44); \
    ROW_STEP_3(word40, word11, word32, word03, word24); \
    ROW_STEP_4(word20, word41, word12, word33, word04); \
                                                        \
    THETA_PREPARE();                                    \
    ROW_STEP_0(word00, word01, word02, word03, word04); \
    IOTA(word00, KECCAK_RC[(firstRound) + 3]);          \
    ROW_STEP_1(word10, word11, word12, word13, word14); \
    ROW_STEP_2(word20, word21, word22, word23, word24); \
    ROW_STEP_3(word30, word31, word32, word33, word34); \
    ROW_STEP_4(word40, word41, word42, word43, word44)

/* 4-way Keccak-f[1600] permutation. One state word = 4 independent 64-bit lanes.
   word<y><x> is state[5*y + x], the same row/column indexing as state[j + i]. */
static void keccakf_x4(__m256i state[25])
{
    __m256i word00 = state[0], word01 = state[1], word02 = state[2], word03 = state[3],
            word04 = state[4];
    __m256i word10 = state[5], word11 = state[6], word12 = state[7], word13 = state[8],
            word14 = state[9];
    __m256i word20 = state[10], word21 = state[11], word22 = state[12], word23 = state[13],
            word24 = state[14];
    __m256i word30 = state[15], word31 = state[16], word32 = state[17], word33 = state[18],
            word34 = state[19];
    __m256i word40 = state[20], word41 = state[21], word42 = state[22], word43 = state[23],
            word44 = state[24];
    __m256i columnParity0, columnParity1, columnParity2, columnParity3, columnParity4;
    __m256i thetaD0, thetaD1, thetaD2, thetaD3, thetaD4;
    __m256i chiIn0, chiIn1, chiIn2, chiIn3, chiIn4;

    FOUR_ROUNDS(0);
    FOUR_ROUNDS(4);
    FOUR_ROUNDS(8);
    FOUR_ROUNDS(12);
    FOUR_ROUNDS(16);
    FOUR_ROUNDS(20);

    state[0]  = word00;
    state[1]  = word01;
    state[2]  = word02;
    state[3]  = word03;
    state[4]  = word04;
    state[5]  = word10;
    state[6]  = word11;
    state[7]  = word12;
    state[8]  = word13;
    state[9]  = word14;
    state[10] = word20;
    state[11] = word21;
    state[12] = word22;
    state[13] = word23;
    state[14] = word24;
    state[15] = word30;
    state[16] = word31;
    state[17] = word32;
    state[18] = word33;
    state[19] = word34;
    state[20] = word40;
    state[21] = word41;
    state[22] = word42;
    state[23] = word43;
    state[24] = word44;
}

#undef THETA_PREPARE
#undef ROW_STEP
#undef ROW_STEP_0
#undef ROW_STEP_1
#undef ROW_STEP_2
#undef ROW_STEP_3
#undef ROW_STEP_4
#undef IOTA
#undef FOUR_ROUNDS

static Ipp64u load64(const Ipp8u* src)
{
    Ipp64u value;
    CopyBlock(src, &value, (cpSize)sizeof(value));
    return value;
}

/* -------- shared sponge over the opaque ctx buffer -------- */

static void shake_x4_init(shake_ctx_x4* ctx, Ipp32s rate)
{
    int i;
    for (i = 0; i < 25; i++)
        ctx->state[i] = _mm256_setzero_si256();
    ctx->rate   = rate;
    ctx->bufPos = 0;
    ctx->absLen = 0;
}

/* Absorb into the sponge, streaming. Bytes accumulate in ctx->block starting at
   ctx->absLen; each time a whole rate-sized block is buffered it is XORed into the state
   and permuted, and any remainder is carried over to the next call. This matches the K0
   asm MB4 absorb, which keeps the same partial-block count in its state word 100, so
   repeated absorbs and inputs longer than the rate produce identical output on both
   tiers. absLen stays in [0, rate-1] on return, which is what finalize needs for the pad
   byte, so no length clamping is required. */
static void shake_x4_absorb(shake_ctx_x4* ctx,
                            const Ipp8u* in0,
                            const Ipp8u* in1,
                            const Ipp8u* in2,
                            const Ipp8u* in3,
                            Ipp32s inlen)
{
    const Ipp8u* inputs[4] = { in0, in1, in2, in3 };
    Ipp32s consumed        = 0;
    int lane, i, rateWords;

    if (inlen <= 0)
        return;

    rateWords = ctx->rate / 8;
    while (consumed < inlen) {
        Ipp32s room  = ctx->rate - ctx->absLen;
        Ipp32s chunk = inlen - consumed;
        if (chunk > room)
            chunk = room;

        for (lane = 0; lane < 4; lane++)
            CopyBlock(inputs[lane] + consumed, ctx->block[lane] + ctx->absLen, (cpSize)chunk);
        ctx->absLen += chunk;
        consumed += chunk;

        if (ctx->absLen == ctx->rate) {
            /* a whole block is buffered: XOR it in, permute, then start a fresh block */
            for (i = 0; i < rateWords; i++) {
                __m256i word  = _mm256_set_epi64x((long long)load64(ctx->block[3] + 8 * i),
                                                 (long long)load64(ctx->block[2] + 8 * i),
                                                 (long long)load64(ctx->block[1] + 8 * i),
                                                 (long long)load64(ctx->block[0] + 8 * i));
                ctx->state[i] = XOR(ctx->state[i], word);
            }
            keccakf_x4(ctx->state);
            ctx->absLen = 0;
        }
    }
    _mm256_zeroupper();
}

static void shake_x4_finalize(shake_ctx_x4* ctx)
{
    int lane, i, rateWords;
    for (lane = 0; lane < 4; lane++) {
        /* zero the unused tail of the partial block before applying the SHAKE pad */
        PadBlock(0, ctx->block[lane] + ctx->absLen, (cpSize)(ctx->rate - ctx->absLen));
        ctx->block[lane][ctx->absLen] ^= 0x1F;   /* SHAKE domain sep + first pad bit */
        ctx->block[lane][ctx->rate - 1] ^= 0x80; /* final pad bit (EOM) */
    }
    rateWords = ctx->rate / 8;
    for (i = 0; i < rateWords; i++) {
        __m256i word  = _mm256_set_epi64x((long long)load64(ctx->block[3] + 8 * i),
                                         (long long)load64(ctx->block[2] + 8 * i),
                                         (long long)load64(ctx->block[1] + 8 * i),
                                         (long long)load64(ctx->block[0] + 8 * i));
        ctx->state[i] = XOR(ctx->state[i], word);
    }
    ctx->bufPos = ctx->rate; /* force a permute on the first squeeze */
    _mm256_zeroupper();
}

static void shake_x4_squeeze(shake_ctx_x4* ctx,
                             Ipp8u* out0,
                             Ipp8u* out1,
                             Ipp8u* out2,
                             Ipp8u* out3,
                             Ipp32s outlen)
{
    Ipp8u* outputs[4] = { out0, out1, out2, out3 };
    int rateWords     = ctx->rate / 8;

    while (outlen > 0) {
        int chunk, lane;
        if (ctx->bufPos == ctx->rate) {
            /* Deinterleave state words -> per-lane blocks. Transpose 4 words at a
               time (4x4 qword transpose) so each lane's 4 words store contiguously,
               instead of a scratch store + 16 byte-copies per group. Tail words
               (rate/8 not a multiple of 4) go scalar. */
            int i = 0;
            keccakf_x4(ctx->state);
            for (; i + 4 <= rateWords; i += 4) {
                __m256i rowWord0 = ctx->state[i], rowWord1 = ctx->state[i + 1];
                __m256i rowWord2 = ctx->state[i + 2], rowWord3 = ctx->state[i + 3];
                __m256i mix0 = _mm256_unpacklo_epi64(rowWord0, rowWord1); /* [a0 b0 a2 b2] */
                __m256i mix1 = _mm256_unpackhi_epi64(rowWord0, rowWord1); /* [a1 b1 a3 b3] */
                __m256i mix2 = _mm256_unpacklo_epi64(rowWord2, rowWord3); /* [c0 d0 c2 d2] */
                __m256i mix3 = _mm256_unpackhi_epi64(rowWord2, rowWord3); /* [c1 d1 c3 d3] */
                __m256i lane0 =
                    _mm256_permute2x128_si256(mix0, mix2, 0x20);          /* lane0 words i..i+3 */
                __m256i lane1 = _mm256_permute2x128_si256(mix1, mix3, 0x20); /* lane1 */
                __m256i lane2 = _mm256_permute2x128_si256(mix0, mix2, 0x31); /* lane2 */
                __m256i lane3 = _mm256_permute2x128_si256(mix1, mix3, 0x31); /* lane3 */
                _mm256_storeu_si256((__m256i*)(ctx->block[0] + 8 * i), lane0);
                _mm256_storeu_si256((__m256i*)(ctx->block[1] + 8 * i), lane1);
                _mm256_storeu_si256((__m256i*)(ctx->block[2] + 8 * i), lane2);
                _mm256_storeu_si256((__m256i*)(ctx->block[3] + 8 * i), lane3);
            }
            for (; i < rateWords; i++) {
                __ALIGN32 Ipp64u laneWords[4];
                _mm256_storeu_si256((__m256i*)laneWords, ctx->state[i]);
                for (lane = 0; lane < 4; lane++)
                    CopyBlock(&laneWords[lane], ctx->block[lane] + 8 * i, 8);
            }
            ctx->bufPos = 0;
        }
        chunk = ctx->rate - ctx->bufPos;
        if (chunk > outlen)
            chunk = outlen;
        for (lane = 0; lane < 4; lane++) {
            CopyBlock(ctx->block[lane] + ctx->bufPos, outputs[lane], (cpSize)chunk);
            outputs[lane] += chunk;
        }
        ctx->bufPos += chunk;
        outlen -= chunk;
    }
    _mm256_zeroupper();
}

/* -------- public MB4 API (shared with the K0 asm), SHAKE128 -------- */

IPP_OWN_DEFN(void, cp_SHA3_SHAKE128_InitMB4, (cpSHA3_SHAKE128Ctx_mb4 * state))
{
    shake_x4_init(ctx_of(state->ctx), SHAKE128_RATE);
}

IPP_OWN_DEFN(void,
             cp_SHA3_SHAKE128_AbsorbMB4,
             (cpSHA3_SHAKE128Ctx_mb4 * state,
              const Ipp8u* in0,
              const Ipp8u* in1,
              const Ipp8u* in2,
              const Ipp8u* in3,
              Ipp64u inlen))
{
    shake_x4_absorb(ctx_of(state->ctx), in0, in1, in2, in3, (Ipp32s)inlen);
}

IPP_OWN_DEFN(void, cp_SHA3_SHAKE128_FinalizeMB4, (cpSHA3_SHAKE128Ctx_mb4 * state))
{
    shake_x4_finalize(ctx_of(state->ctx));
}

IPP_OWN_DEFN(void,
             cp_SHA3_SHAKE128_SqueezeMB4,
             (Ipp8u * out0,
              Ipp8u* out1,
              Ipp8u* out2,
              Ipp8u* out3,
              Ipp64u outlen,
              cpSHA3_SHAKE128Ctx_mb4* state))
{
    shake_x4_squeeze(ctx_of(state->ctx), out0, out1, out2, out3, (Ipp32s)outlen);
}

/* -------- public MB4 API (shared with the K0 asm), SHAKE256 -------- */

IPP_OWN_DEFN(void, cp_SHA3_SHAKE256_InitMB4, (cpSHA3_SHAKE256Ctx_mb4 * state))
{
    shake_x4_init(ctx_of(state->ctx), SHAKE256_RATE);
}

IPP_OWN_DEFN(void,
             cp_SHA3_SHAKE256_AbsorbMB4,
             (cpSHA3_SHAKE256Ctx_mb4 * state,
              const Ipp8u* in0,
              const Ipp8u* in1,
              const Ipp8u* in2,
              const Ipp8u* in3,
              Ipp64u inlen))
{
    shake_x4_absorb(ctx_of(state->ctx), in0, in1, in2, in3, (Ipp32s)inlen);
}

IPP_OWN_DEFN(void, cp_SHA3_SHAKE256_FinalizeMB4, (cpSHA3_SHAKE256Ctx_mb4 * state))
{
    shake_x4_finalize(ctx_of(state->ctx));
}

IPP_OWN_DEFN(void,
             cp_SHA3_SHAKE256_SqueezeMB4,
             (Ipp8u * out0,
              Ipp8u* out1,
              Ipp8u* out2,
              Ipp8u* out3,
              Ipp64u outlen,
              cpSHA3_SHAKE256Ctx_mb4* state))
{
    shake_x4_squeeze(ctx_of(state->ctx), out0, out1, out2, out3, (Ipp32s)outlen);
}

#endif /* #if (_IPP32E == _IPP32E_L9) */
