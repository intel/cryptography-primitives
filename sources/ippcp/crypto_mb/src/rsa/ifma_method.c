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

#include <crypto_mb/rsa.h>
#include <internal/common/ifma_defs.h>
#include <internal/rsa/ifma_rsa_arith.h>
#include <internal/rsa/ifma_rsa_method.h>


#define EXP_WIN_SIZE (5) //(4)

/*
// rsa public key methods
*/
DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA1K_pub65537_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN (RSA_1K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
    static mbx_RSA_Method m = { RSA_ID(RSA_PUB_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN52 * 8 + LEN52 * 8 + MULTIPLE_OF(LEN52, 10) * 8 +
                                      (LEN52 * 8) * 2) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                EXP52x20_pub65537_mb8,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN (RSA_1K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
    static mbx_RSA_Method m = { RSA_ID(RSA_PUB_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN52 * 4 + LEN52 * 4 + MULTIPLE_OF(LEN52, 10) * 4 +
                                      (LEN52 * 4) * 2) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb4,
                                // NULL,
                                EXP52x20_pub65537_mb4,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA2K_pub65537_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN (RSA_2K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
    static mbx_RSA_Method m = { RSA_ID(RSA_PUB_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN52 * 8 + LEN52 * 8 + MULTIPLE_OF(LEN52, 10) * 8 +
                                      (LEN52 * 8) * 2) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                EXP52x40_pub65537_mb8,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN (RSA_2K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
    static mbx_RSA_Method m = { RSA_ID(RSA_PUB_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN52 * 4 + LEN52 * 4 + MULTIPLE_OF(LEN52, 10) * 4 +
                                      (LEN52 * 4) * 2) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb4,
                                // NULL,
                                EXP52x40_pub65537_mb4,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA3K_pub65537_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN (RSA_3K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
    static mbx_RSA_Method m = { RSA_ID(RSA_PUB_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN52 * 8 + LEN52 * 8 + MULTIPLE_OF(LEN52, 10) * 8 +
                                      (LEN52 * 8) * 2) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                EXP52x60_pub65537_mb8,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN (RSA_3K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
    static mbx_RSA_Method m = { RSA_ID(RSA_PUB_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN52 * 4 + LEN52 * 4 + MULTIPLE_OF(LEN52, 10) * 4 +
                                      (LEN52 * 4) * 2) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb4,
                                // NULL,
                                EXP52x60_pub65537_mb4,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA4K_pub65537_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN (RSA_4K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
    static mbx_RSA_Method m = { RSA_ID(RSA_PUB_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN52 * 8 + LEN52 * 8 + MULTIPLE_OF(LEN52, 10) * 8 +
                                      (LEN52 * 8) * 2 + 1) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                EXP52x79_pub65537_mb8,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN (RSA_4K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
    static mbx_RSA_Method m = { RSA_ID(RSA_PUB_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN52 * 4 + LEN52 * 4 + MULTIPLE_OF(LEN52, 10) * 4 +
                                      (LEN52 * 4) * 2 + 1) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb4,
                                // NULL,
                                EXP52x79_pub65537_mb4,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA_pub65537_Method)(int rsaBitsize)
{
    switch (rsaBitsize) {
    case RSA_1K:
        return mbx_RSA1K_pub65537_Method();
    case RSA_2K:
        return mbx_RSA2K_pub65537_Method();
    case RSA_3K:
        return mbx_RSA3K_pub65537_Method();
    case RSA_4K:
        return mbx_RSA4K_pub65537_Method();
    default:
        return NULL;
    }
}


/*
// rsa private key methods
*/
DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA1K_private_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN (RSA_1K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV2_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN64 * 8 + LEN52 * 8 + LEN52 * 8 +
                                      MULTIPLE_OF(LEN52, 10) * 8 + (LEN52 * 8) * 2 +
                                      (LEN64 + 1) * 8 + (1 << EXP_WIN_SIZE) * LEN52 * 8) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                NULL,
                                EXP52x20_mb8,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#undef LEN64
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN (RSA_1K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV2_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN64 * 4 + LEN52 * 4 + LEN52 * 4 +
                                      MULTIPLE_OF(LEN52, 10) * 4 + (LEN52 * 4) * 2 +
                                      (LEN64 + 1) * 4 + (1 << EXP_WIN_SIZE) * LEN52 * 4) *
                                         sizeof(int64u), /* buffer */
                                NULL,
                                EXP52x20_mb4,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#undef LEN64
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA2K_private_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN (RSA_2K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV2_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN64 * 8 + LEN52 * 8 + LEN52 * 8 +
                                      MULTIPLE_OF(LEN52, 10) * 8 + (LEN52 * 8) * 2 +
                                      (LEN64 + 1) * 8 + (1 << EXP_WIN_SIZE) * LEN52 * 8) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                NULL,
                                EXP52x40_mb8,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#undef LEN64
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN (RSA_2K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV2_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN64 * 4 + LEN52 * 4 + LEN52 * 4 +
                                      MULTIPLE_OF(LEN52, 10) * 4 + (LEN52 * 4) * 2 +
                                      (LEN64 + 1) * 4 + (1 << EXP_WIN_SIZE) * LEN52 * 4) *
                                         sizeof(int64u), /* buffer */
                                NULL,
                                EXP52x40_mb4,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#undef LEN64
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA3K_private_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN (RSA_3K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV2_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN64 * 8 + LEN52 * 8 + LEN52 * 8 +
                                      MULTIPLE_OF(LEN52, 10) * 8 + (LEN52 * 8) * 2 +
                                      (LEN64 + 1) * 8 + (1 << EXP_WIN_SIZE) * LEN52 * 8) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                NULL,
                                EXP52x60_mb8,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#undef LEN64
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN (RSA_3K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV2_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN64 * 4 + LEN52 * 4 + LEN52 * 4 +
                                      MULTIPLE_OF(LEN52, 10) * 4 + (LEN52 * 4) * 2 +
                                      (LEN64 + 1) * 4 + (1 << EXP_WIN_SIZE) * LEN52 * 4) *
                                         sizeof(int64u), /* buffer */
                                NULL,
                                EXP52x60_mb4,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#undef LEN64
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA4K_private_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN (RSA_4K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV2_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN64 * 8 + LEN52 * 8 + LEN52 * 8 +
                                      MULTIPLE_OF(LEN52, 10) * 8 + (LEN52 * 8) * 2 + 1 +
                                      (LEN64 + 1) * 8 + (1 << EXP_WIN_SIZE) * LEN52 * 8) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                NULL,
                                EXP52x79_mb8,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#undef LEN64
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN (RSA_4K)
#define LEN52      (NUMBER_OF_DIGITS(RSA_BITLEN, DIGIT_SIZE))
#define LEN64      (NUMBER_OF_DIGITS(RSA_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV2_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN64 * 4 + LEN52 * 4 + LEN52 * 4 +
                                      MULTIPLE_OF(LEN52, 10) * 4 + (LEN52 * 4) * 2 + 1 +
                                      (LEN64 + 1) * 4 + (1 << EXP_WIN_SIZE) * LEN52 * 4) *
                                         sizeof(int64u), /* buffer */
                                NULL,
                                EXP52x79_mb4,
                                NULL,
                                NULL,
                                NULL,
                                NULL };
    return &m;
#undef RSA_BITLEN
#undef LEN52
#undef LEN64
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA_private_Method)(int rsaBitsize)
{
    switch (rsaBitsize) {
    case RSA_1K:
        return mbx_RSA1K_private_Method();
    case RSA_2K:
        return mbx_RSA2K_private_Method();
    case RSA_3K:
        return mbx_RSA3K_private_Method();
    case RSA_4K:
        return mbx_RSA4K_private_Method();
    default:
        return NULL;
    }
}


/*
// rsa private key methods (crt)
*/
DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA1K_private_crt_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN    (RSA_1K)
#define FACTOR_BITLEN (RSA_BITLEN / 2)
#define LEN52         (NUMBER_OF_DIGITS(FACTOR_BITLEN, DIGIT_SIZE))
#define LEN64         (NUMBER_OF_DIGITS(FACTOR_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV5_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN52 * 8 + LEN52 * 8 + LEN64 * 8 + LEN52 * 8 +
                                      LEN52 * 8 + LEN52 * 8 + 2 * LEN52 * 8 + (LEN52 * 8) * 2 +
                                      (LEN64 + 1) * 8 + (1 << EXP_WIN_SIZE) * LEN52 * 8) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                NULL,
                                EXP52x10_mb8,
                                ifma_amred52x10_mb8,
                                ifma_amm52x10_mb8,
                                ifma_modsub52x10_mb8,
                                ifma_addmul52x10_mb8 };
    return &m;
#undef RSA_BITLEN
#undef FACTOR_BITLEN
#undef LEN52
#undef LEN64
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN    (RSA_1K)
#define FACTOR_BITLEN (RSA_BITLEN / 2)
#define LEN52         (NUMBER_OF_DIGITS(FACTOR_BITLEN, DIGIT_SIZE))
#define LEN64         (NUMBER_OF_DIGITS(FACTOR_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV5_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN52 * 4 + LEN52 * 4 + LEN64 * 4 + LEN52 * 4 +
                                      LEN52 * 4 + LEN52 * 4 + 2 * LEN52 * 4 + (LEN52 * 4) * 2 +
                                      (LEN64 + 1) * 4 + (1 << EXP_WIN_SIZE) * LEN52 * 4) *
                                         sizeof(int64u), /* buffer */
                                NULL,
                                EXP52x10_mb4,
                                ifma_amred52x10_mb4,
                                ifma_amm52x10_mb4,
                                ifma_modsub52x10_mb4,
                                ifma_addmul52x10_mb4 };
    return &m;
#undef RSA_BITLEN
#undef FACTOR_BITLEN
#undef LEN52
#undef LEN64
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA2K_private_crt_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN    (RSA_2K)
#define FACTOR_BITLEN (RSA_BITLEN / 2)
#define LEN52         (NUMBER_OF_DIGITS(FACTOR_BITLEN, DIGIT_SIZE))
#define LEN64         (NUMBER_OF_DIGITS(FACTOR_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV5_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN52 * 8 + LEN52 * 8 + LEN64 * 8 + LEN52 * 8 +
                                      LEN52 * 8 + LEN52 * 8 + 2 * LEN52 * 8 + (LEN52 * 8) * 2 +
                                      (LEN64 + 1) * 8 + (1 << EXP_WIN_SIZE) * LEN52 * 8) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                NULL,
                                EXP52x20_mb8,
                                ifma_amred52x20_mb8,
                                ifma_amm52x20_mb8,
                                ifma_modsub52x20_mb8,
                                ifma_addmul52x20_mb8 };
    return &m;
#undef RSA_BITLEN
#undef FACTOR_BITLEN
#undef LEN52
#undef LEN64
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN    (RSA_2K)
#define FACTOR_BITLEN (RSA_BITLEN / 2)
#define LEN52         (NUMBER_OF_DIGITS(FACTOR_BITLEN, DIGIT_SIZE))
#define LEN64         (NUMBER_OF_DIGITS(FACTOR_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV5_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN52 * 4 + LEN52 * 4 + LEN64 * 4 + LEN52 * 4 +
                                      LEN52 * 4 + LEN52 * 4 + 2 * LEN52 * 4 + (LEN52 * 4) * 2 +
                                      (LEN64 + 1) * 4 + (1 << EXP_WIN_SIZE) * LEN52 * 4) *
                                         sizeof(int64u), /* buffer */
                                NULL,
                                EXP52x20_mb4,
                                ifma_amred52x20_mb4,
                                ifma_amm52x20_mb4,
                                ifma_modsub52x20_mb4,
                                ifma_addmul52x20_mb4 };
    return &m;
#undef RSA_BITLEN
#undef FACTOR_BITLEN
#undef LEN52
#undef LEN64
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA3K_private_crt_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN    (RSA_3K)
#define FACTOR_BITLEN (RSA_BITLEN / 2)
#define LEN52         (NUMBER_OF_DIGITS(FACTOR_BITLEN, DIGIT_SIZE))
#define LEN64         (NUMBER_OF_DIGITS(FACTOR_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV5_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN52 * 8 + LEN52 * 8 + LEN64 * 8 + LEN52 * 8 +
                                      LEN52 * 8 + LEN52 * 8 + 2 * LEN52 * 8 + (LEN52 * 8) * 2 +
                                      (LEN64 + 1) * 8 + (1 << EXP_WIN_SIZE) * LEN52 * 8) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                NULL,
                                EXP52x30_mb8,
                                ifma_amred52x30_mb8,
                                ifma_amm52x30_mb8,
                                ifma_modsub52x30_mb8,
                                ifma_addmul52x30_mb8 };
    return &m;
#undef RSA_BITLEN
#undef FACTOR_BITLEN
#undef LEN52
#undef LEN64
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN    (RSA_3K)
#define FACTOR_BITLEN (RSA_BITLEN / 2)
#define LEN52         (NUMBER_OF_DIGITS(FACTOR_BITLEN, DIGIT_SIZE))
#define LEN64         (NUMBER_OF_DIGITS(FACTOR_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV5_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN52 * 4 + LEN52 * 4 + LEN64 * 4 + LEN52 * 4 +
                                      LEN52 * 4 + LEN52 * 4 + 2 * LEN52 * 4 + (LEN52 * 4) * 2 +
                                      (LEN64 + 1) * 4 + (1 << EXP_WIN_SIZE) * LEN52 * 4) *
                                         sizeof(int64u), /* buffer */
                                NULL,
                                EXP52x30_mb4,
                                ifma_amred52x30_mb4,
                                ifma_amm52x30_mb4,
                                ifma_modsub52x30_mb4,
                                ifma_addmul52x30_mb4 };
    return &m;
#undef RSA_BITLEN
#undef FACTOR_BITLEN
#undef LEN52
#undef LEN64
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA4K_private_crt_Method)(void)
{
#if (_MBX >= _MBX_K1)
#define RSA_BITLEN    (RSA_4K)
#define FACTOR_BITLEN (RSA_BITLEN / 2)
#define LEN52         (NUMBER_OF_DIGITS(FACTOR_BITLEN, DIGIT_SIZE))
#define LEN64         (NUMBER_OF_DIGITS(FACTOR_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV5_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (8 + LEN52 * 8 + LEN52 * 8 + LEN64 * 8 + LEN52 * 8 +
                                      LEN52 * 8 + LEN52 * 8 + 2 * LEN52 * 8 + (LEN52 * 8) * 2 + 1 +
                                      (LEN64 + 1) * 8 + (1 << EXP_WIN_SIZE) * LEN52 * 8) *
                                         sizeof(int64u), /* buffer */
                                // ifma_BNU_to_mb8,
                                // NULL,
                                NULL,
                                EXP52x40_mb8,
                                ifma_amred52x40_mb8,
                                ifma_amm52x40_mb8,
                                ifma_modsub52x40_mb8,
                                ifma_addmul52x40_mb8 };
    return &m;
#undef RSA_BITLEN
#undef FACTOR_BITLEN
#undef LEN52
#undef LEN64
#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#define RSA_BITLEN    (RSA_4K)
#define FACTOR_BITLEN (RSA_BITLEN / 2)
#define LEN52         (NUMBER_OF_DIGITS(FACTOR_BITLEN, DIGIT_SIZE))
#define LEN64         (NUMBER_OF_DIGITS(FACTOR_BITLEN, 64))
    static mbx_RSA_Method m = { RSA_ID(RSA_PRV5_KEY, RSA_BITLEN),
                                RSA_BITLEN,
                                64 + (4 + LEN52 * 4 + LEN52 * 4 + LEN64 * 4 + LEN52 * 4 +
                                      LEN52 * 4 + LEN52 * 4 + 2 * LEN52 * 4 + (LEN52 * 4) * 2 + 1 +
                                      (LEN64 + 1) * 4 + (1 << EXP_WIN_SIZE) * LEN52 * 4) *
                                         sizeof(int64u), /* buffer */
                                NULL,
                                EXP52x40_mb4,
                                ifma_amred52x40_mb4,
                                ifma_amm52x40_mb4,
                                ifma_modsub52x40_mb4,
                                ifma_addmul52x40_mb4 };
    return &m;
#undef RSA_BITLEN
#undef FACTOR_BITLEN
#undef LEN52
#undef LEN64
#else
    return NULL;
#endif /* #if (_MBX>=_MBX_K1) */
}

DLL_PUBLIC
const mbx_RSA_Method* OWNAPI(mbx_RSA_private_crt_Method)(int rsaBitsize)
{
    switch (rsaBitsize) {
    case RSA_1K:
        return mbx_RSA1K_private_crt_Method();
    case RSA_2K:
        return mbx_RSA2K_private_crt_Method();
    case RSA_3K:
        return mbx_RSA3K_private_crt_Method();
    case RSA_4K:
        return mbx_RSA4K_private_crt_Method();
    default:
        return NULL;
    }
}

/* size of scratch buffer */
DLL_PUBLIC
int mbx_RSA_Method_BufSize(const mbx_RSA_Method* m)
{
#if ((_MBX <= _MBX_L9) && !(_MBX_AVX_IFMA_SUPPORTED))
    return 0;
#else
    return m ? m->buffSize : 0;
#endif
}
