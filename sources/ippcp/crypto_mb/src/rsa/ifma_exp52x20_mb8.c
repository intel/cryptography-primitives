/*************************************************************************
 * Copyright (C) 2019-2024 Intel Corporation
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


#include <internal/common/ifma_math.h>
#include <internal/rsa/ifma_rsa_arith.h>

#if (_MBX >= _MBX_K1)

#define USE_AMS
#ifdef USE_AMS
#define SQUARE_52x20_mb8(out, Y, mod, k0) \
    AMS52x20_diagonal_mb8((int64u*)(out), (int64u*)(Y), (int64u*)(mod), (int64u*)(k0));
#else
#define SQUARE_52x20_mb8(out, Y, mod, k0) \
    ifma_amm52x20_mb8((int64u*)(out), (int64u*)(Y), (int64u*)(Y), (int64u*)(mod), (int64u*)(k0));
#endif

#define BITSIZE_MODULUS (1024)
#define LEN52           (NUMBER_OF_DIGITS(BITSIZE_MODULUS, DIGIT_SIZE)) // 20
#define LEN64           (NUMBER_OF_DIGITS(BITSIZE_MODULUS, 64))         // 16

// only valid value is 4
// not removed to make code more readable
#define EXP_WIN_SIZE (4)
#define EXP_WIN_MASK ((1 << EXP_WIN_SIZE) - 1)

typedef int64u (*arr_pint64u_x8)[LEN52][8]; // pointer to pre-computed table of base powers

static int64u* extract_multiplier_mb8(int64u out[LEN52][8],
                                      int64u tbl[][LEN52][8],
                                      const int64u idx_mb8[8])
{
    // Assume first element is what's needed
    __m512i X0  = _mm512_load_si512(tbl[0][0]);
    __m512i X1  = _mm512_load_si512(tbl[0][1]);
    __m512i X2  = _mm512_load_si512(tbl[0][2]);
    __m512i X3  = _mm512_load_si512(tbl[0][3]);
    __m512i X4  = _mm512_load_si512(tbl[0][4]);
    __m512i X5  = _mm512_load_si512(tbl[0][5]);
    __m512i X6  = _mm512_load_si512(tbl[0][6]);
    __m512i X7  = _mm512_load_si512(tbl[0][7]);
    __m512i X8  = _mm512_load_si512(tbl[0][8]);
    __m512i X9  = _mm512_load_si512(tbl[0][9]);
    __m512i X10 = _mm512_load_si512(tbl[0][10]);
    __m512i X11 = _mm512_load_si512(tbl[0][11]);
    __m512i X12 = _mm512_load_si512(tbl[0][12]);
    __m512i X13 = _mm512_load_si512(tbl[0][13]);
    __m512i X14 = _mm512_load_si512(tbl[0][14]);
    __m512i X15 = _mm512_load_si512(tbl[0][15]);
    __m512i X16 = _mm512_load_si512(tbl[0][16]);
    __m512i X17 = _mm512_load_si512(tbl[0][17]);
    __m512i X18 = _mm512_load_si512(tbl[0][18]);
    __m512i X19 = _mm512_load_si512(tbl[0][19]);

    __m512i idx_target = _mm512_load_si512(idx_mb8);

    // Find out what we actually need or just keep original
    for (int n = 1; n < (1 << EXP_WIN_SIZE); n++) {
        __m512i idx_curr          = _mm512_set1_epi64(n);
        __mmask8 extract_sel_mask = _mm512_cmpeq_epu64_mask(idx_curr, idx_target);
        X0                        = select64(extract_sel_mask, X0, (U64*)tbl[n][0]);
        X1                        = select64(extract_sel_mask, X1, (U64*)tbl[n][1]);
        X2                        = select64(extract_sel_mask, X2, (U64*)tbl[n][2]);
        X3                        = select64(extract_sel_mask, X3, (U64*)tbl[n][3]);
        X4                        = select64(extract_sel_mask, X4, (U64*)tbl[n][4]);
        X5                        = select64(extract_sel_mask, X5, (U64*)tbl[n][5]);
        X6                        = select64(extract_sel_mask, X6, (U64*)tbl[n][6]);
        X7                        = select64(extract_sel_mask, X7, (U64*)tbl[n][7]);
        X8                        = select64(extract_sel_mask, X8, (U64*)tbl[n][8]);
        X9                        = select64(extract_sel_mask, X9, (U64*)tbl[n][9]);
        X10                       = select64(extract_sel_mask, X10, (U64*)tbl[n][10]);
        X11                       = select64(extract_sel_mask, X11, (U64*)tbl[n][11]);
        X12                       = select64(extract_sel_mask, X12, (U64*)tbl[n][12]);
        X13                       = select64(extract_sel_mask, X13, (U64*)tbl[n][13]);
        X14                       = select64(extract_sel_mask, X14, (U64*)tbl[n][14]);
        X15                       = select64(extract_sel_mask, X15, (U64*)tbl[n][15]);
        X16                       = select64(extract_sel_mask, X16, (U64*)tbl[n][16]);
        X17                       = select64(extract_sel_mask, X17, (U64*)tbl[n][17]);
        X18                       = select64(extract_sel_mask, X18, (U64*)tbl[n][18]);
        X19                       = select64(extract_sel_mask, X19, (U64*)tbl[n][19]);
    }

    _mm512_store_si512(out + 0, X0);
    _mm512_store_si512(out + 1, X1);
    _mm512_store_si512(out + 2, X2);
    _mm512_store_si512(out + 3, X3);
    _mm512_store_si512(out + 4, X4);
    _mm512_store_si512(out + 5, X5);
    _mm512_store_si512(out + 6, X6);
    _mm512_store_si512(out + 7, X7);
    _mm512_store_si512(out + 8, X8);
    _mm512_store_si512(out + 9, X9);
    _mm512_store_si512(out + 10, X10);
    _mm512_store_si512(out + 11, X11);
    _mm512_store_si512(out + 12, X12);
    _mm512_store_si512(out + 13, X13);
    _mm512_store_si512(out + 14, X14);
    _mm512_store_si512(out + 15, X15);
    _mm512_store_si512(out + 16, X16);
    _mm512_store_si512(out + 17, X17);
    _mm512_store_si512(out + 18, X18);
    _mm512_store_si512(out + 19, X19);

    return (int64u*)out;
}


void EXP52x20_mb8(int64u out[][8],
                  const int64u base[][8],
                  const int64u exp[][8],
                  const int64u modulus[][8],
                  const int64u toMont[][8],
                  const int64u k0[8],
                  int64u work_buffer[][8])
{

    /* allocate red(undant) result Y and multiplier X */
    pint64u_x8 red_Y = (pint64u_x8)work_buffer;
    pint64u_x8 red_X = (pint64u_x8)(red_Y + LEN52);

    /* allocate expanded exponent*/
    pint64u_x8 expz = (pint64u_x8)(red_X + LEN52);

    /* pre-computed table of base powers
   red_table[i]  = (base^i)*(2^(LEN52*DIGIT_SIZE)) mod modulus, for i=0, 1, ... , (2^EXP_WIN_SIZE)-1
   redx_table[i] = (base^i)*(2^((LEN52/2)*DIGIT_SIZE)) mod modulus, for i=0, 1, ... , (2^EXP_WIN_SIZE)-1
   */
    arr_pint64u_x8 red_table =
        (arr_pint64u_x8)(expz + LEN64 +
                         1); // total of LEN52<<EXP_WIN_SIZE = LEN52 * 2^EXP_WIN_SIZE arr_pint64u_x8 structures
    arr_pint64u_x8 redx_table = (arr_pint64u_x8)(expz + LEN64 + 1 + (LEN52 << EXP_WIN_SIZE));

    __ALIGN64 U64 mulb[LEN52];
    __ALIGN64 U64 mulbx[LEN52];

    // compute table of powers base^i, i=0, ..., (2^EXP_WIN_SIZE) -1

    zero_mb8(red_X, LEN52);
    _mm512_store_si512(red_X, _mm512_set1_epi64(1));

    // red_table[0] = R = 2^(LEN52*DIGIT_SIZE) mod modulus
    ifma_amm52x20_mb8(
        (int64u*)red_table[0], (int64u*)red_X, (int64u*)toMont, (int64u*)modulus, (int64u*)k0);
    // redx_table[0] = R*2^(-(LEN52/2)*DIGIT_SIZE) mod modulus = 2^((LEN52/2)*DIGIT_SIZE) mod modulus
    ifma_ahmr52x20_mb8(
        (int64u*)redx_table[0], (int64u*)red_table[0], (int64u*)modulus, (int64u*)k0);

    // red_table[1] = base*2^(LEN52*DIGIT_SIZE) mod modulus
    ifma_amm52x20_mb8(
        (int64u*)red_table[1], (int64u*)base, (int64u*)toMont, (int64u*)modulus, (int64u*)k0);
    // redx_table[1] = base*2^((LEN52/2)*DIGIT_SIZE) mod modulus
    ifma_ahmr52x20_mb8(
        (int64u*)redx_table[1], (int64u*)red_table[1], (int64u*)modulus, (int64u*)k0);

    for (int idx = 1; idx < (1 << EXP_WIN_SIZE) / 2; idx++) {
        // red_table[2*idx] = (base^(2*idx))*2^(LEN52*DIGIT_SIZE) mod modulus
        SQUARE_52x20_mb8(
            (int64u*)red_table[2 * idx], (int64u*)red_table[idx], (int64u*)modulus, (int64u*)k0);
        // redx_table[2*idx] = (base^(2*idx))*2^((LEN52/2)*DIGIT_SIZE) mod modulus
        ifma_ahmr52x20_mb8((int64u*)redx_table[2 * idx],
                           (int64u*)red_table[2 * idx],
                           (int64u*)modulus,
                           (int64u*)k0);

        // red_table[2*idx+1] = (base^(2*idx+1))*2^(LEN52*DIGIT_SIZE) mod modulus
        ifma_ahmm52x20_mb8((int64u*)red_table[2 * idx + 1],
                           (int64u*)red_table[2 * idx],
                           (int64u*)red_table[1],
                           (int64u*)redx_table[1],
                           (int64u*)modulus,
                           (int64u*)k0);
        // redx_table[2*idx+1] = (base^(2*idx+1))*2^((LEN52/2)*DIGIT_SIZE) mod modulus
        ifma_ahmr52x20_mb8((int64u*)redx_table[2 * idx + 1],
                           (int64u*)red_table[2 * idx + 1],
                           (int64u*)modulus,
                           (int64u*)k0);
    }

    /* copy and expand exponents */
    copy_mb8(expz, exp, LEN64);
    _mm512_store_si512(expz[LEN64], _mm512_setzero_si512());

    /* exponentiation */
    int rem                = BITSIZE_MODULUS % EXP_WIN_SIZE;
    int delta              = rem ? rem : EXP_WIN_SIZE;
    __m512i table_idx_mask = _mm512_set1_epi64(EXP_WIN_MASK);

    int exp_bit_no      = BITSIZE_MODULUS - delta;
    int exp_chunk_no    = exp_bit_no / 64;
    int exp_chunk_shift = exp_bit_no % 64;

    /* process 1-st exp window - just init result */
    __m512i red_table_idx = _mm512_load_si512(expz[exp_chunk_no]);
    red_table_idx         = _mm512_srli_epi64(red_table_idx, exp_chunk_shift);

    extract_multiplier_mb8(red_Y, red_table, (int64u*)(&red_table_idx));

    /* process other exp windows */
    for (exp_bit_no -= EXP_WIN_SIZE; exp_bit_no >= 0; exp_bit_no -= EXP_WIN_SIZE) {
        __m512i T;
        exp_chunk_no    = exp_bit_no / 64;
        exp_chunk_shift = exp_bit_no % 64;

        red_table_idx = _mm512_load_si512(expz[exp_chunk_no]);
        T             = _mm512_load_si512(expz[exp_chunk_no + 1]);

        red_table_idx = _mm512_srl_epi64(red_table_idx, _mm_set1_epi64x(exp_chunk_shift));
        T             = _mm512_sll_epi64(T, _mm_set1_epi64x(64 - exp_chunk_shift));
        red_table_idx = _mm512_and_si512(_mm512_xor_si512(red_table_idx, T), table_idx_mask);

        /* 4 squarings stitched with extracting pre-computed multiplier from the table */
        AMS4x52x20_diagonal_stitched_with_extract_mb8((int64u*)red_Y,
                                                      (U64*)mulb,
                                                      (U64*)mulbx,
                                                      (int64u*)red_Y,
                                                      (int64u*)modulus,
                                                      (int64u*)k0,
                                                      red_table,
                                                      redx_table,
                                                      (int64u*)(&red_table_idx));

        ifma_ahmm52x20_mb8((int64u*)red_Y,
                           (int64u*)red_Y,
                           (int64u*)mulb,
                           (int64u*)mulbx,
                           (int64u*)modulus,
                           (int64u*)k0);
    }

    /* clear exponents */
    zero_mb8(expz, LEN64);

    /* convert result back in regular 2^DIGIT_SIZE domain */
    zero_mb8(red_X, LEN52);
    _mm512_store_si512(red_X, _mm512_set1_epi64(1));
    ifma_amm52x20_mb8((int64u*)out, (int64u*)red_Y, (int64u*)red_X, (int64u*)modulus, (int64u*)k0);
}

#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

#include <internal/rsa/avxifma_extract_multiplier.h>
#include <assert.h>

#define USE_AMS
#ifdef USE_AMS
#define SQUARE_52x20_mb4(out, Y, mod, k0) \
    AMS52x20_diagonal_mb4((int64u*)(out), (int64u*)(Y), (int64u*)(mod), (int64u*)(k0));
#else
#define SQUARE_52x20_mb4(out, Y, mod, k0) \
    ifma_amm52x20_mb4((int64u*)(out), (int64u*)(Y), (int64u*)(Y), (int64u*)(mod), (int64u*)(k0));
#endif

#define BITSIZE_MODULUS (1024)
#define LEN52           (NUMBER_OF_DIGITS(BITSIZE_MODULUS, DIGIT_SIZE)) // 20
#define LEN64           (NUMBER_OF_DIGITS(BITSIZE_MODULUS, 64))         // 16

// only valid value is 4
// not removed to make code more readable
#define EXP_WIN_SIZE    (4)
#define EXP_WIN_MASK    ((1 << EXP_WIN_SIZE) - 1)

typedef int64u (*arr_pint64u_x4)[LEN52][4]; // pointer to pre-computed table of base powers

static void extract_multiplier_mb4(int64u out[LEN52][4],
                                   int64u tbl[][LEN52][4],
                                   const __m256i idx_target)
{
    extract_multiplier_mb4_N((__m256i*)out, (const __m256i*)tbl, idx_target, LEN52, EXP_WIN_SIZE);
}

void EXP52x20_mb4(int64u out[][4],
                  const int64u base[][4],
                  const int64u exp[][4],
                  const int64u modulus[][4],
                  const int64u toMont[][4],
                  const int64u k0[4],
                  int64u work_buffer[][4])
{
    /* other window sizes are not supported at the moment */
    assert(EXP_WIN_SIZE == 4);

    /* allocate red(undant) result Y and multiplier X */
    pint64u_x4 red_Y = (pint64u_x4)work_buffer;
    pint64u_x4 red_X = (pint64u_x4)(red_Y + LEN52);

    /* allocate expanded exponent*/
    pint64u_x4 expz = (pint64u_x4)(red_X + LEN52);

    /*
    * pre-computed table of base powers
    * red_table[i]  = (base^i)*(2^(LEN52*DIGIT_SIZE)) mod modulus, for i=0, 1, ... , (2^EXP_WIN_SIZE)-1
    * redx_table[i] = (base^i)*(2^((LEN52/2)*DIGIT_SIZE)) mod modulus, for i=0, 1, ... , (2^EXP_WIN_SIZE)-1
    */
    arr_pint64u_x4 red_table =
        (arr_pint64u_x4)(expz + LEN64 +
                         1); // total of LEN52<<EXP_WIN_SIZE = LEN52 * 2^EXP_WIN_SIZE arr_pint64u_x4 structures
    arr_pint64u_x4 redx_table = (arr_pint64u_x4)(expz + LEN64 + 1 + (LEN52 << EXP_WIN_SIZE));

    __ALIGN64 int64u_x4 mulb[LEN52];
    __ALIGN64 int64u_x4 mulbx[LEN52];

    // compute table of powers base^i, i=0, ..., (2^EXP_WIN_SIZE) -1
    _mm256_storeu_si256((__m256i*)red_X, _mm256_set1_epi64x(1));
    zero_mb4(&red_X[1], LEN52 - 1); /* table[0] = mont(x^0) = mont(1) */

    // red_table[0] = R = 2^(LEN52*DIGIT_SIZE) mod modulus
    ifma_amm52x20_mb4(
        (int64u*)red_table[0], (int64u*)red_X, (int64u*)toMont, (int64u*)modulus, (int64u*)k0);
    // redx_table[0] = R*2^(-(LEN52/2)*DIGIT_SIZE) mod modulus = 2^((LEN52/2)*DIGIT_SIZE) mod modulus
    ifma_ahmr52x20_mb4(
        (int64u*)redx_table[0], (int64u*)red_table[0], (int64u*)modulus, (int64u*)k0);

    // red_table[1] = base*2^(LEN52*DIGIT_SIZE) mod modulus
    ifma_amm52x20_mb4(
        (int64u*)red_table[1], (int64u*)base, (int64u*)toMont, (int64u*)modulus, (int64u*)k0);
    // redx_table[1] = base*2^((LEN52/2)*DIGIT_SIZE) mod modulus
    ifma_ahmr52x20_mb4(
        (int64u*)redx_table[1], (int64u*)red_table[1], (int64u*)modulus, (int64u*)k0);

    for (int idx = 1; idx < (1 << EXP_WIN_SIZE) / 2; idx++) {
        // red_table[2*idx] = (base^(2*idx))*2^(LEN52*DIGIT_SIZE) mod modulus
        SQUARE_52x20_mb4(
            (int64u*)red_table[2 * idx], (int64u*)red_table[idx], (int64u*)modulus, (int64u*)k0);

        // redx_table[2*idx] = (base^(2*idx))*2^((LEN52/2)*DIGIT_SIZE) mod modulus
        ifma_ahmr52x20_mb4((int64u*)redx_table[2 * idx],
                           (int64u*)red_table[2 * idx],
                           (int64u*)modulus,
                           (int64u*)k0);

        // red_table[2*idx+1] = (base^(2*idx+1))*2^(LEN52*DIGIT_SIZE) mod modulus
        ifma_ahmm52x20_mb4((int64u*)red_table[2 * idx + 1],
                           (int64u*)red_table[2 * idx],
                           (int64u*)red_table[1],
                           (int64u*)redx_table[1],
                           (int64u*)modulus,
                           (int64u*)k0);
        // redx_table[2*idx+1] = (base^(2*idx+1))*2^((LEN52/2)*DIGIT_SIZE) mod modulus
        ifma_ahmr52x20_mb4((int64u*)redx_table[2 * idx + 1],
                           (int64u*)red_table[2 * idx + 1],
                           (int64u*)modulus,
                           (int64u*)k0);
    }

    /* copy and expand exponents */
    copy_mb4(expz, exp, LEN64);
    _mm256_store_si256((__m256i*)&expz[LEN64], _mm256_setzero_si256());

    /* exponentiation */
    const int rem                = BITSIZE_MODULUS % EXP_WIN_SIZE;
    const int delta              = rem ? rem : EXP_WIN_SIZE;
    const __m256i table_idx_mask = _mm256_set1_epi64x(EXP_WIN_MASK);

    int exp_bit_no = BITSIZE_MODULUS - delta;

    /* process 1-st exp window - just init result */
    __m256i red_table_idx0 = ((const __m256i*)expz[exp_bit_no / 64])[0];

    red_table_idx0 = _mm256_srli_epi64(red_table_idx0, exp_bit_no % 64);

    extract_multiplier_mb4(red_Y, red_table, red_table_idx0);

    /* process other exp windows */
    for (exp_bit_no -= EXP_WIN_SIZE; exp_bit_no >= 0; exp_bit_no -= EXP_WIN_SIZE) {
        const int exp_chunk_no      = exp_bit_no / 64;
        const int exp_chunk_shift   = exp_bit_no % 64;
        const __m128i shift_right_n = _mm_set1_epi64x(exp_chunk_shift);
        const __m128i shift_left_n  = _mm_set1_epi64x(64 - (exp_chunk_shift));

        red_table_idx0 = ((const __m256i*)expz[exp_chunk_no])[0];
        red_table_idx0 = _mm256_srl_epi64(red_table_idx0, shift_right_n);

        const __m256i T0 =
            _mm256_sll_epi64(((const __m256i*)expz[exp_chunk_no + 1])[0], shift_left_n);

        red_table_idx0 = _mm256_and_si256(_mm256_xor_si256(red_table_idx0, T0), table_idx_mask);

        /* 4 squarings stitched with extracting pre-computed multiplier from the table */
        AMS4x52x20_diagonal_stitched_with_extract_mb4((int64u*)red_Y,
                                                      (U64*)mulb,
                                                      (U64*)mulbx,
                                                      (int64u*)red_Y,
                                                      (int64u*)modulus,
                                                      (int64u*)k0,
                                                      red_table,
                                                      redx_table,
                                                      red_table_idx0);

        ifma_ahmm52x20_mb4((int64u*)red_Y,
                           (int64u*)red_Y,
                           (int64u*)mulb,
                           (int64u*)mulbx,
                           (int64u*)modulus,
                           (int64u*)k0);
    }

    /* clear exponents */
    zero_mb4(expz, LEN64);

    /* convert result back in regular 2^DIGIT_SIZE domain */
    _mm256_store_si256((__m256i*)red_X, _mm256_set1_epi64x(1));
    zero_mb4(&red_X[1], LEN52 - 1);

    ifma_amm52x20_mb4((int64u*)out, (int64u*)red_Y, (int64u*)red_X, (int64u*)modulus, (int64u*)k0);
}

#endif /* #if (_MBX >= _MBX_K1) */
