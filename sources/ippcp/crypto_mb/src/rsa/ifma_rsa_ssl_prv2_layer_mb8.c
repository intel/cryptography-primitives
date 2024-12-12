typedef int to_avoid_translation_unit_is_empty_warning;

#ifndef BN_OPENSSL_DISABLE

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

#include <openssl/bn.h>

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_cvt52.h>
#include <internal/rsa/ifma_rsa_arith.h>

#if (_MBX >= _MBX_K1)

#define EXP_WIN_SIZE (5) //(4)
#define EXP_WIN_MASK ((1 << EXP_WIN_SIZE) - 1)

/*
// y = x^d mod n
*/

void ifma_ssl_rsa1K_prv2_layer_mb8(const int8u* const from_pa[8],
                                   int8u* const to_pa[8],
                                   const BIGNUM* const d_pa[8],
                                   const BIGNUM* const n_pa[8])
{
#define RSA_BITLEN (RSA_1K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))

    /* allocate mb8 buffers */
    __ALIGN64 int64u k0_mb8[8];
    __ALIGN64 int64u d_mb8[LEN64][8];
    __ALIGN64 int64u rr_mb8[LEN52][8];
    __ALIGN64 int64u inout_mb8[LEN52][8];
    /* MULTIPLE_OF_10 because of AMS5x52x79_diagonal_mb8() implementation specific */
    __ALIGN64 int64u n_mb8[MULTIPLE_OF(LEN52, 10)][8];
    /* allocate stack for red(undant) result, multiplier, for exponent X and for pre-computed table of base powers */
    __ALIGN64 int64u work_buffer[LEN52 * 2 + 1 + (LEN64 + 1) + (1 << EXP_WIN_SIZE) * LEN52][8];

    /* convert modulus to ifma fmt */
    zero_mb8(n_mb8, MULTIPLE_OF(LEN52, 10));
    ifma_BN_to_mb8(n_mb8, n_pa, RSA_BITLEN);

    /* compute k0[] */
    ifma_montFactor52_mb8(k0_mb8, n_mb8[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb8(rr_mb8, n_mb8, RSA_BITLEN);

    /* convert input to ifma fmt */
    ifma_HexStr8_to_mb8(inout_mb8, from_pa, RSA_BITLEN);

    /* re-arrange exps to ifma */
    ifma_BN_transpose_copy(d_mb8, d_pa, RSA_BITLEN);

    /* exponentiation */
    EXP52x20_mb8(inout_mb8,
                 (const int64u(*)[8])inout_mb8,
                 (const int64u(*)[8])d_mb8,
                 (const int64u(*)[8])n_mb8,
                 (const int64u(*)[8])rr_mb8,
                 k0_mb8,
                 (int64u(*)[8])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb8_to_HexStr8(to_pa, (const int64u(*)[8])inout_mb8, RSA_BITLEN);

    /* clear exponents */
    zero_mb8(d_mb8, LEN64);

#undef RSA_BITLEN
#undef LEN52
#undef LEN64
}


void ifma_ssl_rsa2K_prv2_layer_mb8(const int8u* const from_pa[8],
                                   int8u* const to_pa[8],
                                   const BIGNUM* const d_pa[8],
                                   const BIGNUM* const n_pa[8])
{
#define RSA_BITLEN (RSA_2K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))

    /* allocate mb8 buffers */
    __ALIGN64 int64u k0_mb8[8];
    __ALIGN64 int64u d_mb8[LEN64][8];
    __ALIGN64 int64u rr_mb8[LEN52][8];
    __ALIGN64 int64u inout_mb8[LEN52][8];
    /* MULTIPLE_OF_10 because of AMS5x52x79_diagonal_mb8() implementation specific */
    __ALIGN64 int64u n_mb8[MULTIPLE_OF(LEN52, 10)][8];
    /* allocate stack for red(undant) result, multiplier, for exponent X and for pre-computed table of base powers */
    __ALIGN64 int64u work_buffer[LEN52 * 2 + 1 + (LEN64 + 1) + (1 << EXP_WIN_SIZE) * LEN52][8];

    /* convert modulus to ifma fmt */
    zero_mb8(n_mb8, MULTIPLE_OF(LEN52, 10));
    ifma_BN_to_mb8(n_mb8, n_pa, RSA_BITLEN);

    /* compute k0[] */
    ifma_montFactor52_mb8(k0_mb8, n_mb8[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb8(rr_mb8, n_mb8, RSA_BITLEN);

    /* convert input to ifma fmt */
    ifma_HexStr8_to_mb8(inout_mb8, from_pa, RSA_BITLEN);

    /* re-arrange exps to ifma */
    ifma_BN_transpose_copy(d_mb8, d_pa, RSA_BITLEN);

    /* exponentiation */
    EXP52x40_mb8(inout_mb8,
                 (const int64u(*)[8])inout_mb8,
                 (const int64u(*)[8])d_mb8,
                 (const int64u(*)[8])n_mb8,
                 (const int64u(*)[8])rr_mb8,
                 k0_mb8,
                 (int64u(*)[8])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb8_to_HexStr8(to_pa, (const int64u(*)[8])inout_mb8, RSA_BITLEN);

    /* clear exponents */
    zero_mb8(d_mb8, LEN64);

#undef RSA_BITLEN
#undef LEN52
#undef LEN64
}


void ifma_ssl_rsa3K_prv2_layer_mb8(const int8u* const from_pa[8],
                                   int8u* const to_pa[8],
                                   const BIGNUM* const d_pa[8],
                                   const BIGNUM* const n_pa[8])
{
#define RSA_BITLEN (RSA_3K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))

    /* allocate mb8 buffers */
    __ALIGN64 int64u k0_mb8[8];
    __ALIGN64 int64u d_mb8[LEN64][8];
    __ALIGN64 int64u rr_mb8[LEN52][8];
    __ALIGN64 int64u inout_mb8[LEN52][8];
    /* MULTIPLE_OF_10 because of AMS5x52x79_diagonal_mb8() implementation specific */
    __ALIGN64 int64u n_mb8[MULTIPLE_OF(LEN52, 10)][8];
    /* allocate stack for red(undant) result, multiplier, for exponent X and for pre-computed table of base powers */
    __ALIGN64 int64u work_buffer[LEN52 * 2 + 1 + (LEN64 + 1) + (1 << EXP_WIN_SIZE) * LEN52][8];

    /* convert modulus to ifma fmt */
    zero_mb8(n_mb8, MULTIPLE_OF(LEN52, 10));
    ifma_BN_to_mb8(n_mb8, n_pa, RSA_BITLEN);

    /* compute k0[] */
    ifma_montFactor52_mb8(k0_mb8, n_mb8[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb8(rr_mb8, n_mb8, RSA_BITLEN);

    /* convert input to ifma fmt */
    ifma_HexStr8_to_mb8(inout_mb8, from_pa, RSA_BITLEN);

    /* re-arrange exps to ifma */
    ifma_BN_transpose_copy(d_mb8, d_pa, RSA_BITLEN);

    /* exponentiation */
    EXP52x60_mb8(inout_mb8,
                 (const int64u(*)[8])inout_mb8,
                 (const int64u(*)[8])d_mb8,
                 (const int64u(*)[8])n_mb8,
                 (const int64u(*)[8])rr_mb8,
                 k0_mb8,
                 (int64u(*)[8])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb8_to_HexStr8(to_pa, (const int64u(*)[8])inout_mb8, RSA_BITLEN);

    /* clear exponents */
    zero_mb8(d_mb8, LEN64);

#undef RSA_BITLEN
#undef LEN52
#undef LEN64
}


void ifma_ssl_rsa4K_prv2_layer_mb8(const int8u* const from_pa[8],
                                   int8u* const to_pa[8],
                                   const BIGNUM* const d_pa[8],
                                   const BIGNUM* const n_pa[8])
{
#define RSA_BITLEN (RSA_4K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))

    /* allocate mb8 buffers */
    __ALIGN64 int64u k0_mb8[8];
    __ALIGN64 int64u d_mb8[LEN64][8];
    __ALIGN64 int64u rr_mb8[LEN52][8];
    __ALIGN64 int64u inout_mb8[LEN52][8];
    /* MULTIPLE_OF_10 because of AMS5x52x79_diagonal_mb8() implementation specific */
    __ALIGN64 int64u n_mb8[MULTIPLE_OF(LEN52, 10)][8];
    /* allocate stack for red(undant) result, multiplier, for exponent X and for pre-computed table of base powers */
    __ALIGN64 int64u work_buffer[LEN52 * 2 + 1 + (LEN64 + 1) + (1 << EXP_WIN_SIZE) * LEN52][8];

    /* convert modulus to ifma fmt */
    zero_mb8(n_mb8, MULTIPLE_OF(LEN52, 10));
    ifma_BN_to_mb8(n_mb8, n_pa, RSA_BITLEN);

    /* compute k0[] */
    ifma_montFactor52_mb8(k0_mb8, n_mb8[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb8(rr_mb8, n_mb8, RSA_BITLEN);

    /* convert input to ifma fmt */
    ifma_HexStr8_to_mb8(inout_mb8, from_pa, RSA_BITLEN);

    /* re-arrange exps to ifma */
    ifma_BN_transpose_copy(d_mb8, d_pa, RSA_BITLEN);

    /* exponentiation */
    EXP52x79_mb8(inout_mb8,
                 (const int64u(*)[8])inout_mb8,
                 (const int64u(*)[8])d_mb8,
                 (const int64u(*)[8])n_mb8,
                 (const int64u(*)[8])rr_mb8,
                 k0_mb8,
                 (int64u(*)[8])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb8_to_HexStr8(to_pa, (const int64u(*)[8])inout_mb8, RSA_BITLEN);

    /* clear exponents */
    zero_mb8(d_mb8, LEN64);

#undef RSA_BITLEN
#undef LEN52
#undef LEN64
}

#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

#define EXP_WIN_SIZE (5) //(4)
#define EXP_WIN_MASK ((1 << EXP_WIN_SIZE) - 1)

/*
// y = x^d mod n
*/

void ifma_ssl_rsa1K_prv2_layer_mb4(const int8u* const from_pa[4],
                                   int8u* const to_pa[4],
                                   const BIGNUM* const d_pa[4],
                                   const BIGNUM* const n_pa[4])
{
#define RSA_BITLEN   (RSA_1K)
#define LEN52        (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64        (NUMBER_OF_DIGITS(RSA_BITLEN, 64))

    /* allocate mb4 buffers */
    __ALIGN64 int64u k0_mb4[4];
    __ALIGN64 int64u d_mb4[LEN64][4];
    __ALIGN64 int64u rr_mb4[LEN52][4];
    __ALIGN64 int64u inout_mb4[LEN52][4];
    /* MULTIPLE_OF_10 because of AMS5x52x79_diagonal_mb4() implementation specific */
    __ALIGN64 int64u n_mb4[MULTIPLE_OF(LEN52, 10)][4];
    /* allocate stack for red(undant) result, multiplier, for exponent X and for pre-computed table of base powers */
    __ALIGN64 int64u work_buffer[LEN52 * 2 + 1 + (LEN64 + 1) + (1 << EXP_WIN_SIZE) * LEN52][4];

    /* convert modulus to ifma fmt */
    zero_mb4(n_mb4, MULTIPLE_OF(LEN52, 10));
    ifma_BN_to_mb4(n_mb4, n_pa, RSA_BITLEN);

    /* compute k0[] */
    ifma_montFactor52_mb4(k0_mb4, n_mb4[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb4(rr_mb4, n_mb4, RSA_BITLEN);

    /* convert input to ifma fmt */
    ifma_HexStr4_to_mb4(inout_mb4, from_pa, RSA_BITLEN);

    /* re-arrange exps to ifma */
    ifma_BN_transpose_copy_mb4(d_mb4, d_pa, RSA_BITLEN);

    /* exponentiation */
    EXP52x20_mb4(inout_mb4,
                 (const int64u(*)[4])inout_mb4,
                 (const int64u(*)[4])d_mb4,
                 (const int64u(*)[4])n_mb4,
                 (const int64u(*)[4])rr_mb4,
                 k0_mb4,
                 (int64u(*)[4])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb4_to_HexStr4(to_pa, (const int64u(*)[4])inout_mb4, RSA_BITLEN);

    /* clear exponents */
    zero_mb4(d_mb4, LEN64);

#undef RSA_BITLEN
#undef LEN52
#undef LEN64
}


void ifma_ssl_rsa2K_prv2_layer_mb4(const int8u* const from_pa[4],
                                   int8u* const to_pa[4],
                                   const BIGNUM* const d_pa[4],
                                   const BIGNUM* const n_pa[4])
{
#define RSA_BITLEN (RSA_2K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))

    /* allocate mb4 buffers */
    __ALIGN64 int64u k0_mb4[4];
    __ALIGN64 int64u d_mb4[LEN64][4];
    __ALIGN64 int64u rr_mb4[LEN52][4];
    __ALIGN64 int64u inout_mb4[LEN52][4];
    /* MULTIPLE_OF_10 because of AMS5x52x79_diagonal_mb4() implementation specific */
    __ALIGN64 int64u n_mb4[MULTIPLE_OF(LEN52, 10)][4];
    /* allocate stack for red(undant) result, multiplier, for exponent X and for pre-computed table of base powers */
    __ALIGN64 int64u work_buffer[LEN52 * 2 + 1 + (LEN64 + 1) + (1 << EXP_WIN_SIZE) * LEN52][4];

    /* convert modulus to ifma fmt */
    zero_mb4(n_mb4, MULTIPLE_OF(LEN52, 10));
    ifma_BN_to_mb4(n_mb4, n_pa, RSA_BITLEN);

    /* compute k0[] */
    ifma_montFactor52_mb4(k0_mb4, n_mb4[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb4(rr_mb4, n_mb4, RSA_BITLEN);

    /* convert input to ifma fmt */
    ifma_HexStr4_to_mb4(inout_mb4, from_pa, RSA_BITLEN);

    /* re-arrange exps to ifma */
    ifma_BN_transpose_copy_mb4(d_mb4, d_pa, RSA_BITLEN);

    /* exponentiation */
    EXP52x40_mb4(inout_mb4,
                 (const int64u(*)[4])inout_mb4,
                 (const int64u(*)[4])d_mb4,
                 (const int64u(*)[4])n_mb4,
                 (const int64u(*)[4])rr_mb4,
                 k0_mb4,
                 (int64u(*)[4])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb4_to_HexStr4(to_pa, (const int64u(*)[4])inout_mb4, RSA_BITLEN);

    /* clear exponents */
    zero_mb4(d_mb4, LEN64);

#undef RSA_BITLEN
#undef LEN52
#undef LEN64
}


void ifma_ssl_rsa3K_prv2_layer_mb4(const int8u* const from_pa[4],
                                   int8u* const to_pa[4],
                                   const BIGNUM* const d_pa[4],
                                   const BIGNUM* const n_pa[4])
{
#define RSA_BITLEN (RSA_3K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))

    /* allocate mb4 buffers */
    __ALIGN64 int64u k0_mb4[4];
    __ALIGN64 int64u d_mb4[LEN64][4];
    __ALIGN64 int64u rr_mb4[LEN52][4];
    __ALIGN64 int64u inout_mb4[LEN52][4];
    /* MULTIPLE_OF_10 because of AMS5x52x79_diagonal_mb4() implementation specific */
    __ALIGN64 int64u n_mb4[MULTIPLE_OF(LEN52, 10)][4];
    /* allocate stack for red(undant) result, multiplier, for exponent X and for pre-computed table of base powers */
    __ALIGN64 int64u work_buffer[LEN52 * 2 + 1 + (LEN64 + 1) + (1 << EXP_WIN_SIZE) * LEN52][4];

    /* convert modulus to ifma fmt */
    zero_mb4(n_mb4, MULTIPLE_OF(LEN52, 10));
    ifma_BN_to_mb4(n_mb4, n_pa, RSA_BITLEN);

    /* compute k0[] */
    ifma_montFactor52_mb4(k0_mb4, n_mb4[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb4(rr_mb4, n_mb4, RSA_BITLEN);

    /* convert input to ifma fmt */
    ifma_HexStr4_to_mb4(inout_mb4, from_pa, RSA_BITLEN);

    /* re-arrange exps to ifma */
    ifma_BN_transpose_copy_mb4(d_mb4, d_pa, RSA_BITLEN);

    /* exponentiation */
    EXP52x60_mb4(inout_mb4,
                 (const int64u(*)[4])inout_mb4,
                 (const int64u(*)[4])d_mb4,
                 (const int64u(*)[4])n_mb4,
                 (const int64u(*)[4])rr_mb4,
                 k0_mb4,
                 (int64u(*)[4])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb4_to_HexStr4(to_pa, (const int64u(*)[4])inout_mb4, RSA_BITLEN);

    /* clear exponents */
    zero_mb4(d_mb4, LEN64);

#undef RSA_BITLEN
#undef LEN52
#undef LEN64
}


void ifma_ssl_rsa4K_prv2_layer_mb4(const int8u* const from_pa[4],
                                   int8u* const to_pa[4],
                                   const BIGNUM* const d_pa[4],
                                   const BIGNUM* const n_pa[4])
{
#define RSA_BITLEN (RSA_4K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))

    /* allocate mb4 buffers */
    __ALIGN64 int64u k0_mb4[4];
    __ALIGN64 int64u d_mb4[LEN64][4];
    __ALIGN64 int64u rr_mb4[LEN52][4];
    __ALIGN64 int64u inout_mb4[LEN52][4];
    /* MULTIPLE_OF_10 because of AMS5x52x79_diagonal_mb4() implementation specific */
    __ALIGN64 int64u n_mb4[MULTIPLE_OF(LEN52, 10)][4];
    /* allocate stack for red(undant) result, multiplier, for exponent X and for pre-computed table of base powers */
    __ALIGN64 int64u work_buffer[LEN52 * 2 + 1 + (LEN64 + 1) + (1 << EXP_WIN_SIZE) * LEN52][4];

    /* convert modulus to ifma fmt */
    zero_mb4(n_mb4, MULTIPLE_OF(LEN52, 10));
    ifma_BN_to_mb4(n_mb4, n_pa, RSA_BITLEN);

    /* compute k0[] */
    ifma_montFactor52_mb4(k0_mb4, n_mb4[0]);

    /* compute to_Montgomery domain converters */
    ifma_montRR52x_mb4(rr_mb4, n_mb4, RSA_BITLEN);

    /* convert input to ifma fmt */
    ifma_HexStr4_to_mb4(inout_mb4, from_pa, RSA_BITLEN);

    /* re-arrange exps to ifma */
    ifma_BN_transpose_copy_mb4(d_mb4, d_pa, RSA_BITLEN);

    /* exponentiation */
    EXP52x79_mb4(inout_mb4,
                 (const int64u(*)[4])inout_mb4,
                 (const int64u(*)[4])d_mb4,
                 (const int64u(*)[4])n_mb4,
                 (const int64u(*)[4])rr_mb4,
                 k0_mb4,
                 (int64u(*)[4])work_buffer);

    /* convert result from ifma fmt */
    ifma_mb4_to_HexStr4(to_pa, (const int64u(*)[4])inout_mb4, RSA_BITLEN);

    /* clear exponents */
    zero_mb4(d_mb4, LEN64);

#undef RSA_BITLEN
#undef LEN52
#undef LEN64
}


#endif /* #if (_MBX >= _MBX_K1) */

#endif /* BN_OPENSSL_DISABLE */
