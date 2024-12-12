/*************************************************************************
* Copyright (C) 2019 Intel Corporation
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

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_math.h>

#include <assert.h>

#define PROC_LEN (52)

#define BYTES_REV (1)
#define RADIX_CVT (2)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#if (_MBX >= _MBX_K1)

#if defined(_MSC_VER) && (_MSC_VER < 1920)
// Disable optimization for VS2017 due to AVX512 masking bug
#define DISABLE_OPTIMIZATION __pragma(optimize("", off))
#else
#define DISABLE_OPTIMIZATION
#endif

__MBX_INLINE __mmask8 MB_MASK(int L) { return (L > 0) ? (__mmask8)0xFF : (__mmask8)0; }

__MBX_INLINE __mmask64 SB_MASK1(int L, int REV)
{
    if (L <= 0)
        return (__mmask64)0x0;
    if (L > PROC_LEN)
        L = PROC_LEN;
    if (REV)
        return (__mmask64)(0xFFFFFFFFFFFFFFFFULL << ((int)sizeof(__m512i) - L));
    return (__mmask64)(0xFFFFFFFFFFFFFFFFULL >> ((int)sizeof(__m512i) - L));
}


#ifndef BN_OPENSSL_DISABLE
#include <openssl/bn.h>
#if BN_OPENSSL_PATCH
extern BN_ULONG* bn_get_words(const BIGNUM* bn);
#endif
#endif /* BN_OPENSSL_DISABLE */

/*
// transpose 8 SB into MB including (reverse bytes and) radix 2^64 => 2^52 conversion
//
// covers:
//    - 8 BIGNUM     -> mb8
//    - 8 BNU        -> mb8
//    - 8 hex strings -> mb8
*/
DISABLE_OPTIMIZATION
__MBX_INLINE void transform_8sb_to_mb8(U64 out_mb8[],
                                       int bitLen,
                                       int8u* inp[8],
                                       int inpLen[8],
                                       int flag)
{
    // inverse bytes (reverse=1)
    const __m512i bswap_mask = _mm512_set_epi64(0x0001020304050607,
                                                0x08090a0b0c0d0e0f,
                                                0x1011121314151617,
                                                0x18191a1b1c1d1e1f,
                                                0x2021222324252627,
                                                0x28292a2b2c2d2e2f,
                                                0x3031323334353637,
                                                0x38393a3b3c3d3e3f);
    // repeat words
    const __m512i idx16 = _mm512_set_epi64(0x0019001800170016,
                                           0x0016001500140013,
                                           0x0013001200110010,
                                           0x0010000f000e000d,
                                           0x000c000b000a0009,
                                           0x0009000800070006,
                                           0x0006000500040003,
                                           0x0003000200010000);
    // shift right
    const __m512i shiftR = _mm512_set_epi64(12, 8, 4, 0, 12, 8, 4, 0);
    // radix 2^52 mask of digits
    __m512i digMask = _mm512_set1_epi64(DIGIT_MASK);

    int bytesRev = flag & BYTES_REV;                      /* reverse flag */
    int radixCvt = flag & RADIX_CVT;                      /* radix (64->52) conversion assumed*/

    int inpBytes  = NUMBER_OF_DIGITS(bitLen, 8);          /* bytes */
    int outDigits = NUMBER_OF_DIGITS(bitLen, DIGIT_SIZE); /* digits */

    int i;
    for (i = 0; inpBytes > 0; i += PROC_LEN, inpBytes -= PROC_LEN, out_mb8 += 8) {
        int sbidx = bytesRev ? inpBytes - (int)sizeof(__m512i) : i;

        __m512i X0 =
            _mm512_maskz_loadu_epi8(SB_MASK1(inpLen[0] - i, bytesRev), (__m512i*)&inp[0][sbidx]);
        __m512i X1 =
            _mm512_maskz_loadu_epi8(SB_MASK1(inpLen[1] - i, bytesRev), (__m512i*)&inp[1][sbidx]);
        __m512i X2 =
            _mm512_maskz_loadu_epi8(SB_MASK1(inpLen[2] - i, bytesRev), (__m512i*)&inp[2][sbidx]);
        __m512i X3 =
            _mm512_maskz_loadu_epi8(SB_MASK1(inpLen[3] - i, bytesRev), (__m512i*)&inp[3][sbidx]);
        __m512i X4 =
            _mm512_maskz_loadu_epi8(SB_MASK1(inpLen[4] - i, bytesRev), (__m512i*)&inp[4][sbidx]);
        __m512i X5 =
            _mm512_maskz_loadu_epi8(SB_MASK1(inpLen[5] - i, bytesRev), (__m512i*)&inp[5][sbidx]);
        __m512i X6 =
            _mm512_maskz_loadu_epi8(SB_MASK1(inpLen[6] - i, bytesRev), (__m512i*)&inp[6][sbidx]);
        __m512i X7 =
            _mm512_maskz_loadu_epi8(SB_MASK1(inpLen[7] - i, bytesRev), (__m512i*)&inp[7][sbidx]);

        if (bytesRev) {
            X0 = _mm512_permutexvar_epi8(bswap_mask, X0);
            X1 = _mm512_permutexvar_epi8(bswap_mask, X1);
            X2 = _mm512_permutexvar_epi8(bswap_mask, X2);
            X3 = _mm512_permutexvar_epi8(bswap_mask, X3);
            X4 = _mm512_permutexvar_epi8(bswap_mask, X4);
            X5 = _mm512_permutexvar_epi8(bswap_mask, X5);
            X6 = _mm512_permutexvar_epi8(bswap_mask, X6);
            X7 = _mm512_permutexvar_epi8(bswap_mask, X7);
        }

        if (radixCvt) {
            X0 = _mm512_permutexvar_epi16(idx16, X0);
            X0 = _mm512_srlv_epi64(X0, shiftR);
            X0 = _mm512_and_si512(X0, digMask); /* probably exceeded instruction */

            X1 = _mm512_permutexvar_epi16(idx16, X1);
            X1 = _mm512_srlv_epi64(X1, shiftR);
            X1 = _mm512_and_si512(X1, digMask);

            X2 = _mm512_permutexvar_epi16(idx16, X2);
            X2 = _mm512_srlv_epi64(X2, shiftR);
            X2 = _mm512_and_si512(X2, digMask);

            X3 = _mm512_permutexvar_epi16(idx16, X3);
            X3 = _mm512_srlv_epi64(X3, shiftR);
            X3 = _mm512_and_si512(X3, digMask);

            X4 = _mm512_permutexvar_epi16(idx16, X4);
            X4 = _mm512_srlv_epi64(X4, shiftR);
            X4 = _mm512_and_si512(X4, digMask);

            X5 = _mm512_permutexvar_epi16(idx16, X5);
            X5 = _mm512_srlv_epi64(X5, shiftR);
            X5 = _mm512_and_si512(X5, digMask);

            X6 = _mm512_permutexvar_epi16(idx16, X6);
            X6 = _mm512_srlv_epi64(X6, shiftR);
            X6 = _mm512_and_si512(X6, digMask);

            X7 = _mm512_permutexvar_epi16(idx16, X7);
            X7 = _mm512_srlv_epi64(X7, shiftR);
            X7 = _mm512_and_si512(X7, digMask);
        }

        // transpose 8 digits at a time
        TRANSPOSE_8xI64x8(X0, X1, X2, X3, X4, X5, X6, X7);

        // store transposed digits
        _mm512_mask_storeu_epi64(&out_mb8[0], MB_MASK(outDigits--), X0);
        _mm512_mask_storeu_epi64(&out_mb8[1], MB_MASK(outDigits--), X1);
        _mm512_mask_storeu_epi64(&out_mb8[2], MB_MASK(outDigits--), X2);
        _mm512_mask_storeu_epi64(&out_mb8[3], MB_MASK(outDigits--), X3);
        _mm512_mask_storeu_epi64(&out_mb8[4], MB_MASK(outDigits--), X4);
        _mm512_mask_storeu_epi64(&out_mb8[5], MB_MASK(outDigits--), X5);
        _mm512_mask_storeu_epi64(&out_mb8[6], MB_MASK(outDigits--), X6);
        _mm512_mask_storeu_epi64(&out_mb8[7], MB_MASK(outDigits--), X7);
    }
}

#ifndef BN_OPENSSL_DISABLE
// Convert BIGNUM into MB8(Radix=2^52) format
// Returns bitmask of successfully converted values
// Accepts NULLs as BIGNUM inputs
//    Null or wrong length
int8u ifma_BN_to_mb8(int64u out_mb8[][8], const BIGNUM* const bn[8], int bitLen)
{
    // check input input length
    assert((0 < bitLen) && (bitLen <= IFMA_MAX_BITSIZE));

    int byteLen = NUMBER_OF_DIGITS(bitLen, 8);
    int byteLens[8];

    int8u* d[8];
#ifndef BN_OPENSSL_PATCH
    __ALIGN64 int8u buffer[8][NUMBER_OF_DIGITS(IFMA_MAX_BITSIZE, 8)];
#endif

    int i;
    for (i = 0; i < 8; ++i) {
        if (NULL != bn[i]) {
            byteLens[i] = BN_num_bytes(bn[i]);
            assert(byteLens[i] <= byteLen);

#ifndef BN_OPENSSL_PATCH
            d[i] = buffer[i];
            BN_bn2lebinpad(bn[i], d[i], byteLen);
#else
            d[i] = (int8u*)bn_get_words(bn[i]);
#endif
        } else {
            // no input in that bucket
            d[i]        = NULL;
            byteLens[i] = 0;
        }
    }

    transform_8sb_to_mb8((U64*)out_mb8, bitLen, (int8u**)d, byteLens, RADIX_CVT);

    return _mm512_cmpneq_epi64_mask(_mm512_loadu_si512((__m512i*)bn), _mm512_setzero_si512());
}
#endif /* BN_OPENSSL_DISABLE */

// Similar to ifma_BN_to_mb8(), but converts array of int64u instead of BIGNUM
// Assumed that each converted values has bitLen length
int8u ifma_BNU_to_mb8(int64u out_mb8[][8], const int64u* const bn[8], int bitLen)
{
    // Check input parameters
    assert(bitLen > 0);

    int byteLens[8];
    int byteLen = NUMBER_OF_DIGITS(bitLen, 8);
    int i;
    for (i = 0; i < 8; ++i)
        byteLens[i] = (NULL != bn[i]) ? byteLen : 0;

    transform_8sb_to_mb8((U64*)out_mb8, bitLen, (int8u**)bn, byteLens, RADIX_CVT);

    return _mm512_cmpneq_epi64_mask(_mm512_loadu_si512((__m512i*)bn), _mm512_setzero_si512());
}

int8u ifma_HexStr8_to_mb8(int64u out_mb8[][8], const int8u* const pStr[8], int bitLen)
{
    // check input parameters
    assert(bitLen > 0);

    int byteLens[8];
    int byteLen = NUMBER_OF_DIGITS(bitLen, 8);
    int i;
    for (i = 0; i < 8; i++)
        byteLens[i] = (NULL != pStr[i]) ? byteLen : 0;

    transform_8sb_to_mb8((U64*)out_mb8, bitLen, (int8u**)pStr, byteLens, RADIX_CVT | BYTES_REV);

    return _mm512_cmpneq_epi64_mask(_mm512_loadu_si512((__m512i*)pStr), _mm512_setzero_si512());
}
////////////////////////////////////////////////////////////////////////////////////////////////////

/*
// transpose MB into 8 SB including (reverse bytes and) radix 2^52 => 2^64 conversion
//
// covers:
//    - mb8 -> 8 BNU
//    - mb8 -> 8 hex strings
*/
DISABLE_OPTIMIZATION
__MBX_INLINE void transform_mb8_to_8sb(int8u* out[8],
                                       int outLen[8],
                                       const U64 inp_mb8[],
                                       int bitLen,
                                       int flag)
{
    // inverse bytes (reverse=1)
    /* clang-format off */
    const __m512i bswap_mask = _mm512_set_epi64(
                     0x0001020304050607, 0x08090a0b0c0d0e0f,
                     0x1011121314151617, 0x18191a1b1c1d1e1f,
                     0x2021222324252627, 0x28292a2b2c2d2e2f,
                     0x3031323334353637, 0x38393a3b3c3d3e3f);
    /* clang-format on */

    const __m512i shiftL = _mm512_set_epi64(4, 0, 4, 0, 4, 0, 4, 0);

    const __m512i permutation1 = _mm512_set_epi64(0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
                                                  0x3f3f3f3f3e3d3c3b,  // {63,63,63,63,62,61,60,59}
                                                  0x3737363534333231,  // {55,55,54,53,52,51,50,49}
                                                  0x302e2d2c2b2a2928,  // {48,46,45,44,43,42,41,40}
                                                  0x1f1f1f1f1f1f1e1d,  // {31,31,31,31,31,31,30,29}
                                                  0x1717171716151413,  // {23,23,23,23,22,21,20,19}
                                                  0x0f0f0f0e0d0c0b0a,  // {15,15,15,14,13,12,11,10}
                                                  0x0706050403020100); // { 7, 6, 5, 4, 3, 2, 1, 0}

    const __m512i permutation2 = _mm512_set_epi64(0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
                                                  0x3f3f3f3f3f3f3f3f,  // {63,63,63,63,63,63,63,63}
                                                  0x3a39383737373737,  // {58,57,56,55,55,55,55,55}
                                                  0x2727272727272726,  // {39,39,39,39,39,39,39,38}
                                                  0x2524232221201f1f,  // {37,36,35,34,33,32,31,31}
                                                  0x1c1b1a1918171717,  // {28,27,26,25,24,23,23,23}
                                                  0x1211100f0f0f0f0f,  // {18,17,16,15,15,15,15,15}
                                                  0x0908070707070707); // { 9, 8, 7, 7, 7, 7, 7, 7}
    int bytesRev               = flag & BYTES_REV;                     /* reverse flag */
    int radixCvt               = flag & RADIX_CVT;        /* radix (52->64) conversion assumed */

    int inpDigits = NUMBER_OF_DIGITS(bitLen, DIGIT_SIZE); /* digits */
    int outBytes  = NUMBER_OF_DIGITS(bitLen, 8);          /* bytes */

    int i;
    for (i = 0; outBytes > 0; i += PROC_LEN, outBytes -= PROC_LEN, inp_mb8 += 8) {
        int sbidx = bytesRev ? outBytes - (int)sizeof(__m512i) : i;

        __m512i X0 = _mm512_maskz_loadu_epi64(MB_MASK(inpDigits--), &inp_mb8[0]);
        __m512i X1 = _mm512_maskz_loadu_epi64(MB_MASK(inpDigits--), &inp_mb8[1]);
        __m512i X2 = _mm512_maskz_loadu_epi64(MB_MASK(inpDigits--), &inp_mb8[2]);
        __m512i X3 = _mm512_maskz_loadu_epi64(MB_MASK(inpDigits--), &inp_mb8[3]);
        __m512i X4 = _mm512_maskz_loadu_epi64(MB_MASK(inpDigits--), &inp_mb8[4]);
        __m512i X5 = _mm512_maskz_loadu_epi64(MB_MASK(inpDigits--), &inp_mb8[5]);
        __m512i X6 = _mm512_maskz_loadu_epi64(MB_MASK(inpDigits--), &inp_mb8[6]);
        __m512i X7 = _mm512_maskz_loadu_epi64(MB_MASK(inpDigits--), &inp_mb8[7]);

        // transpose 8 digits at a time
        TRANSPOSE_8xI64x8(X0, X1, X2, X3, X4, X5, X6, X7);

        if (radixCvt) {
            __m512i T;
            X0 = _mm512_sllv_epi64(X0, shiftL);
            T  = _mm512_permutexvar_epi8(permutation1, X0);
            X0 = _mm512_permutexvar_epi8(permutation2, X0);
            X0 = _mm512_or_si512(X0, T);

            X1 = _mm512_sllv_epi64(X1, shiftL);
            T  = _mm512_permutexvar_epi8(permutation1, X1);
            X1 = _mm512_permutexvar_epi8(permutation2, X1);
            X1 = _mm512_or_si512(X1, T);

            X2 = _mm512_sllv_epi64(X2, shiftL);
            T  = _mm512_permutexvar_epi8(permutation1, X2);
            X2 = _mm512_permutexvar_epi8(permutation2, X2);
            X2 = _mm512_or_si512(X2, T);

            X3 = _mm512_sllv_epi64(X3, shiftL);
            T  = _mm512_permutexvar_epi8(permutation1, X3);
            X3 = _mm512_permutexvar_epi8(permutation2, X3);
            X3 = _mm512_or_si512(X3, T);

            X4 = _mm512_sllv_epi64(X4, shiftL);
            T  = _mm512_permutexvar_epi8(permutation1, X4);
            X4 = _mm512_permutexvar_epi8(permutation2, X4);
            X4 = _mm512_or_si512(X4, T);

            X5 = _mm512_sllv_epi64(X5, shiftL);
            T  = _mm512_permutexvar_epi8(permutation1, X5);
            X5 = _mm512_permutexvar_epi8(permutation2, X5);
            X5 = _mm512_or_si512(X5, T);

            X6 = _mm512_sllv_epi64(X6, shiftL);
            T  = _mm512_permutexvar_epi8(permutation1, X6);
            X6 = _mm512_permutexvar_epi8(permutation2, X6);
            X6 = _mm512_or_si512(X6, T);

            X7 = _mm512_sllv_epi64(X7, shiftL);
            T  = _mm512_permutexvar_epi8(permutation1, X7);
            X7 = _mm512_permutexvar_epi8(permutation2, X7);
            X7 = _mm512_or_si512(X7, T);
        }

        if (bytesRev) {
            X0 = _mm512_permutexvar_epi8(bswap_mask, X0);
            X1 = _mm512_permutexvar_epi8(bswap_mask, X1);
            X2 = _mm512_permutexvar_epi8(bswap_mask, X2);
            X3 = _mm512_permutexvar_epi8(bswap_mask, X3);
            X4 = _mm512_permutexvar_epi8(bswap_mask, X4);
            X5 = _mm512_permutexvar_epi8(bswap_mask, X5);
            X6 = _mm512_permutexvar_epi8(bswap_mask, X6);
            X7 = _mm512_permutexvar_epi8(bswap_mask, X7);
        }

        // store transposed digits
        _mm512_mask_storeu_epi8(out[0] + sbidx, SB_MASK1(outLen[0] - i, bytesRev), X0);
        _mm512_mask_storeu_epi8(out[1] + sbidx, SB_MASK1(outLen[1] - i, bytesRev), X1);
        _mm512_mask_storeu_epi8(out[2] + sbidx, SB_MASK1(outLen[2] - i, bytesRev), X2);
        _mm512_mask_storeu_epi8(out[3] + sbidx, SB_MASK1(outLen[3] - i, bytesRev), X3);
        _mm512_mask_storeu_epi8(out[4] + sbidx, SB_MASK1(outLen[4] - i, bytesRev), X4);
        _mm512_mask_storeu_epi8(out[5] + sbidx, SB_MASK1(outLen[5] - i, bytesRev), X5);
        _mm512_mask_storeu_epi8(out[6] + sbidx, SB_MASK1(outLen[6] - i, bytesRev), X6);
        _mm512_mask_storeu_epi8(out[7] + sbidx, SB_MASK1(outLen[7] - i, bytesRev), X7);
    }
}

int8u ifma_mb8_to_BNU(int64u* const out_bn[8], const int64u inp_mb8[][8], const int bitLen)
{
    // Check input parameters
    assert(bitLen > 0);

    int bnu_bitlen = NUMBER_OF_DIGITS(bitLen, 64) * 64; // gres: output length is multiple 64
    int byteLens[8];
    int i;
    for (i = 0; i < 8; ++i)
        //gres: byteLens[i] = (NULL != out_bn[i]) ? NUMBER_OF_DIGITS(bitLen, 8) : 0;
        byteLens[i] = (NULL != out_bn[i]) ? NUMBER_OF_DIGITS(bnu_bitlen, 8) : 0;

    transform_mb8_to_8sb((int8u**)out_bn, byteLens, (U64*)inp_mb8, bitLen, RADIX_CVT);

    return _mm512_cmpneq_epi64_mask(_mm512_loadu_si512((__m512i*)out_bn), _mm512_setzero_si512());
}

int8u ifma_mb8_to_HexStr8(int8u* const pStr[8], const int64u inp_mb8[][8], int bitLen)
{
    // check input parameters
    assert(bitLen > 0);

    int byteLens[8];
    int byteLen = NUMBER_OF_DIGITS(bitLen, 8);
    int i;
    for (i = 0; i < 8; i++)
        byteLens[i] = (NULL != pStr[i]) ? byteLen : 0;

    transform_mb8_to_8sb((int8u**)pStr, byteLens, (U64*)inp_mb8, bitLen, RADIX_CVT | BYTES_REV);

    return _mm512_cmpneq_epi64_mask(_mm512_loadu_si512((__m512i*)pStr), _mm512_setzero_si512());
}
////////////////////////////////////////////////////////////////////////////////////////////////////

/*
// transpose 8 SB into MB without radix conversion
//
// covers:
//    - mb8 -> 8 BNU
//    - mb8 -> 8 hex strings
*/
DISABLE_OPTIMIZATION
int8u ifma_BNU_transpose_copy(int64u out_mb8[][8], const int64u* const bn[8], int bitLen)
{
    // Check input parameters
    assert(bitLen > 0);

    __mmask8 kbn[8];
    int i;
    for (i = 0; i < 8; ++i)
        kbn[i] = (NULL == bn[i]) ? (__mmask8)0 : (__mmask8)0xFF;

    int len = NUMBER_OF_DIGITS(bitLen, 64);
    int n;
    for (n = 0; len > 0; n += 8, out_mb8 += 8) {
        __mmask8 kread = (len >= 8) ? 0xFF : (__mmask8)((1 << len) - 1);

        __m512i X0 = _mm512_maskz_loadu_epi64(kread & kbn[0], bn[0] + n);
        __m512i X1 = _mm512_maskz_loadu_epi64(kread & kbn[1], bn[1] + n);
        __m512i X2 = _mm512_maskz_loadu_epi64(kread & kbn[2], bn[2] + n);
        __m512i X3 = _mm512_maskz_loadu_epi64(kread & kbn[3], bn[3] + n);
        __m512i X4 = _mm512_maskz_loadu_epi64(kread & kbn[4], bn[4] + n);
        __m512i X5 = _mm512_maskz_loadu_epi64(kread & kbn[5], bn[5] + n);
        __m512i X6 = _mm512_maskz_loadu_epi64(kread & kbn[6], bn[6] + n);
        __m512i X7 = _mm512_maskz_loadu_epi64(kread & kbn[7], bn[7] + n);

        TRANSPOSE_8xI64x8(X0, X1, X2, X3, X4, X5, X6, X7);

        _mm512_mask_storeu_epi64(&out_mb8[0], MB_MASK(len--), X0);
        _mm512_mask_storeu_epi64(&out_mb8[1], MB_MASK(len--), X1);
        _mm512_mask_storeu_epi64(&out_mb8[2], MB_MASK(len--), X2);
        _mm512_mask_storeu_epi64(&out_mb8[3], MB_MASK(len--), X3);
        _mm512_mask_storeu_epi64(&out_mb8[4], MB_MASK(len--), X4);
        _mm512_mask_storeu_epi64(&out_mb8[5], MB_MASK(len--), X5);
        _mm512_mask_storeu_epi64(&out_mb8[6], MB_MASK(len--), X6);
        _mm512_mask_storeu_epi64(&out_mb8[7], MB_MASK(len--), X7);
    }

    return _mm512_cmpneq_epi64_mask(_mm512_loadu_si512((__m512i*)bn), _mm512_setzero_si512());
}

#ifndef BN_OPENSSL_DISABLE
DISABLE_OPTIMIZATION
int8u ifma_BN_transpose_copy(int64u out_mb8[][8], const BIGNUM* const bn[8], int bitLen)
{
    // check input length
    assert((0 < bitLen) && (bitLen <= IFMA_MAX_BITSIZE));

    int byteLen = NUMBER_OF_DIGITS(bitLen, 64) * 8;

    int64u* inp[8];
#ifndef BN_OPENSSL_PATCH
    __ALIGN64 int64u buffer[8][NUMBER_OF_DIGITS(IFMA_MAX_BITSIZE, 64)];
#endif

    __mmask8 kbn[8];

    int i;
    for (i = 0; i < 8; ++i) {
        if (NULL == bn[i]) {
            kbn[i] = 0;
            inp[i] = NULL;
        } else {
            kbn[i] = 0xFF;

#ifndef BN_OPENSSL_PATCH
            inp[i] = buffer[i];
            BN_bn2lebinpad(bn[i], (unsigned char*)inp[i], byteLen);
#else
            inp[i] = (int64u*)bn_get_words(bn[i]);
#endif
        }
    }

    int len = NUMBER_OF_DIGITS(bitLen, 64);
    int n;
    for (n = 0; len > 0; n += 8, out_mb8 += 8) {
        __mmask8 k = (len >= 8) ? 0xFF : (1 << len) - 1;

        __m512i X0 = _mm512_maskz_loadu_epi64(k & kbn[0], inp[0] + n);
        __m512i X1 = _mm512_maskz_loadu_epi64(k & kbn[1], inp[1] + n);
        __m512i X2 = _mm512_maskz_loadu_epi64(k & kbn[2], inp[2] + n);
        __m512i X3 = _mm512_maskz_loadu_epi64(k & kbn[3], inp[3] + n);
        __m512i X4 = _mm512_maskz_loadu_epi64(k & kbn[4], inp[4] + n);
        __m512i X5 = _mm512_maskz_loadu_epi64(k & kbn[5], inp[5] + n);
        __m512i X6 = _mm512_maskz_loadu_epi64(k & kbn[6], inp[6] + n);
        __m512i X7 = _mm512_maskz_loadu_epi64(k & kbn[7], inp[7] + n);

        TRANSPOSE_8xI64x8(X0, X1, X2, X3, X4, X5, X6, X7);

        _mm512_mask_storeu_epi64(&out_mb8[0], MB_MASK(len--), X0);
        _mm512_mask_storeu_epi64(&out_mb8[1], MB_MASK(len--), X1);
        _mm512_mask_storeu_epi64(&out_mb8[2], MB_MASK(len--), X2);
        _mm512_mask_storeu_epi64(&out_mb8[3], MB_MASK(len--), X3);
        _mm512_mask_storeu_epi64(&out_mb8[4], MB_MASK(len--), X4);
        _mm512_mask_storeu_epi64(&out_mb8[5], MB_MASK(len--), X5);
        _mm512_mask_storeu_epi64(&out_mb8[6], MB_MASK(len--), X6);
        _mm512_mask_storeu_epi64(&out_mb8[7], MB_MASK(len--), X7);
    }

    return _mm512_cmpneq_epi64_mask(_mm512_loadu_si512((__m512i*)bn), _mm512_setzero_si512());
}
#endif /* BN_OPENSSL_DISABLE */

#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

#include <internal/common/mem_fns.h>

#define PROC_LEN2 (PROC_LEN / 2)

#ifndef BN_OPENSSL_DISABLE
#include <openssl/bn.h>
#if BN_OPENSSL_PATCH
extern BN_ULONG* bn_get_words(const BIGNUM* bn);
#endif
#endif /* BN_OPENSSL_DISABLE */

__MBX_INLINE void transpose_4x64bx4(__m256i* w0, __m256i* w1, __m256i* w2, __m256i* w3)
{
    const __m256i r0 = _mm256_permute2x128_si256(*w0, *w2, 0x20);
    const __m256i r1 = _mm256_permute2x128_si256(*w1, *w3, 0x20);
    const __m256i r2 = _mm256_permute2x128_si256(*w0, *w2, 0x31);
    const __m256i r3 = _mm256_permute2x128_si256(*w1, *w3, 0x31);

    /*
     * Structure at this point:
     * r0 = {c1 c0 a1 a0}
     * r1 = {d1 d0 b1 b0}
     * r2 = {c3 c2 a3 a2}
     * r3 = {d3 d2 b3 b2}
     */

    *w0 = _mm256_castps_si256(
        _mm256_shuffle_ps(_mm256_castsi256_ps(r0), _mm256_castsi256_ps(r1), 0x44));
    *w1 = _mm256_castps_si256(
        _mm256_shuffle_ps(_mm256_castsi256_ps(r0), _mm256_castsi256_ps(r1), 0xee));
    *w2 = _mm256_castps_si256(
        _mm256_shuffle_ps(_mm256_castsi256_ps(r2), _mm256_castsi256_ps(r3), 0x44));
    *w3 = _mm256_castps_si256(
        _mm256_shuffle_ps(_mm256_castsi256_ps(r2), _mm256_castsi256_ps(r3), 0xee));

    /*
     * Output structure:
     * w0 = {d0 c0 b0 a0}
     * w1 = {d1 c1 b1 a1}
     * w2 = {d2 c2 b2 a2}
     * w3 = {d3 c3 b3 a3}
     */
}

#if defined(_MSC_VER) && !defined(__clang__)
#pragma optimize("", off)
#endif

MBX_ZEROING_FUNC_ATTRIBUTES
void zero_u256(int8u* buffer)
{
#if defined(__GNUC__)
    // Avoid dead code elimination for GNU compilers
    ASM("");
#endif

    _mm256_storeu_si256((__m256i*)buffer, _mm256_setzero_si256());
}

#if defined(_MSC_VER) && !defined(__clang__)
#pragma optimize("", on)
#endif

/*
// transpose 4 SB into MB including (reverse bytes and) radix 2^64 => 2^52 conversion
//
// covers:
//    - 4 BIGNUM     -> mb4
//    - 4 BNU        -> mb4
//    - 4 hex strings -> mb4
*/
__MBX_INLINE void transform_4sb_to_mb4(U64 out_mb4[],
                                       const int bitLen,
                                       const int8u* inp[4],
                                       int inpLen[4],
                                       const int flag)
{
    const int bytesRev = flag & BYTES_REV;               /* reverse flag */
    const int radixCvt = flag & RADIX_CVT;               /* radix (64->52) conversion assumed*/

    int inpBytes          = NUMBER_OF_DIGITS(bitLen, 8); /* bytes */
    int outDigits         = NUMBER_OF_DIGITS(bitLen, DIGIT_SIZE); /* digits */
    __m256i* out_mb4_simd = (__m256i*)out_mb4;

    for (int i = 0; inpBytes > 0; i += PROC_LEN2, inpBytes -= PROC_LEN2, out_mb4_simd += 4) {
        __m256i X[4];

        if (bytesRev) {
            // inverse bytes (reverse=1)
            const int sbidx = inpBytes;

#define BUFFER_LEN ((PROC_LEN2 + 31) & (~31))
            int8u buffer[BUFFER_LEN];

            for (int k = 0; k < 4; k++) {
                if (i >= inpLen[k]) {
                    X[k] = _mm256_setzero_si256();
                    continue;
                }

                const int L1            = inpLen[k] - i;
                const int L2            = L1 > PROC_LEN2 ? PROC_LEN2 : L1;
                const int8u* ptr        = &inp[k][sbidx - L2];
                const __m128i swap_mask = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);

                /*
                 * load  [ 0..15 | xx xx xx xx xx xx A6 A7   A8 A9 AA AB AC AD AE AF]
                 *       [16..31 | B0 B1 B2 B3 B4 B5 B6 B7   B8 B9 BA BB BC BD BE BF]
                 */

                if (L2 != PROC_LEN2) {
                    PadBlock(0, buffer, PROC_LEN2 - L2);
                    CopyBlock(ptr, &buffer[PROC_LEN2 - L2], L2);
                    ptr = buffer;
                }

                __m128i t128a = _mm_loadu_si128((const __m128i*)&ptr[0]);
                __m128i t128b = _mm_loadu_si128((const __m128i*)&ptr[10]);

                t128a = _mm_bslli_si128(t128a, 6);
                t128a = _mm_shuffle_epi8(t128a, swap_mask);
                t128b = _mm_shuffle_epi8(t128b, swap_mask);

                /*
                 * store [ 0..15 | BF BE BD BC BB BA B9 B8   B7 B6 B5 B4 B3 B2 B1 B0]
                 *       [16..31 | AF AE AD AC AB AA A9 A8   A7 A6 xx xx xx xx xx xx]
                 */

                X[k] = _mm256_inserti128_si256(_mm256_castsi128_si256(t128b), t128a, 1);
            }

            zero_u256(buffer);

        } else {
            const int sbidx = i;

            for (int k = 0; k < 4; k++) {
                if (i >= inpLen[k]) {
                    X[k] = _mm256_setzero_si256();
                    continue;
                }

                const int L1 = inpLen[k] - i;
                const int L2 = L1 > PROC_LEN2 ? PROC_LEN2 : L1;

                if (L2 == PROC_LEN2) {
                    const int8u* ptr    = &inp[k][sbidx];
                    const __m128i t128a = _mm_loadu_si128((const __m128i*)&ptr[0]);
                    __m128i t128b       = _mm_loadu_si128((const __m128i*)&ptr[10]);

                    t128b = _mm_bsrli_si128(t128b, 6);

                    X[k] = _mm256_inserti128_si256(_mm256_castsi128_si256(t128a), t128b, 1);
                } else {
                    __m256i buffer = _mm256_setzero_si256();

                    CopyBlock(&inp[k][sbidx], &buffer, L2);
                    X[k] = buffer;
                }
            }
        }

        if (radixCvt) {
            // convert consecutive 26 bytes spread across X[i] into
            // 4 x 64 bit words, each word consisting of:
            //   bits 63:52 - zero
            //   bits 51:0  - message

            // shift right
            const __m256i shiftRight = _mm256_set_epi64x(4, 0, 4, 0);
            // radix 2^52 mask of digits
            const __m256i mask52b = _mm256_set1_epi64x(DIGIT_MASK);
            // repeat one byte
            /* clang-format off */
            const __m128i cvt104b_2x52b =
                        _mm_set_epi8(0xff, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06,
                                     0xff, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00);
            /* clang-format on */

            for (int k = 0; k < 4; k++) {
                // split 32 bytes into 2 x 16 bytes
                const __m128i l0 = _mm256_castsi256_si128(X[k]);
                const __m128i l1 = _mm256_extracti128_si256(X[k], 1);

                // use alignr to create 4 x (2 x 52 bits) data chunks
                const __m128i l0_13b = _mm_shuffle_epi8(l0, cvt104b_2x52b);
                const __m128i l1_13b =
                    _mm_shuffle_epi8(_mm_alignr_epi8(l1, l0, 1 * 13), cvt104b_2x52b);

                // put back the chunks into 32 byte chunks
                const __m256i l01_26b =
                    _mm256_inserti128_si256(_mm256_castsi128_si256(l0_13b), l1_13b, 1);

                // do the final shift right and & before storing into the buffer
                X[k] = _mm256_and_si256(_mm256_srlv_epi64(l01_26b, shiftRight), mask52b);
            }
        }

        /*
         * X[0] = A0 A1 A2 A3
         * X[1] = B0 B1 B2 B3
         * X[2] = C0 C1 C2 C3
         * X[3] = D0 D1 D2 D3
         */

        transpose_4x64bx4(&X[0], &X[1], &X[2], &X[3]);

        /*
         * X[0] = A0 B0 C0 D0
         * X[1] = A1 B1 C1 D1
         * X[2] = A2 B2 C2 D2
         * X[3] = A3 B3 C3 D3
         */

        // store transposed digits
        for (int k = 0; (k < 4) && (outDigits > 0); k++, outDigits--)
            _mm256_storeu_si256((__m256i*)&out_mb4_simd[k], X[k]);
    }
}

#ifndef BN_OPENSSL_DISABLE
// Convert BIGNUM into MB4(Radix=2^52) format
// Returns bitmask of successfully converted values
// Accepts NULLs as BIGNUM inputs
//    Null or wrong length
int8u ifma_BN_to_mb4(int64u out_mb4[][4], const BIGNUM* const bn[4], int bitLen)
{
    // check input input length
    assert((0 < bitLen) && (bitLen <= IFMA_MAX_BITSIZE));

    int byteLen = NUMBER_OF_DIGITS(bitLen, 8);
    int byteLens[4];

    int8u* d[4];
#ifndef BN_OPENSSL_PATCH
    __ALIGN64 int8u buffer[4][NUMBER_OF_DIGITS(IFMA_MAX_BITSIZE, 8)];
#endif

    int8u retVal = 0;
    int i;

    for (i = 0; i < 4; ++i) {
        if (NULL != bn[i]) {
            byteLens[i] = BN_num_bytes(bn[i]);
            assert(byteLens[i] <= byteLen);

#ifndef BN_OPENSSL_PATCH
            d[i] = buffer[i];
            BN_bn2lebinpad(bn[i], d[i], byteLen);
#else
            d[i] = (int8u*)bn_get_words(bn[i]);
#endif
            retVal |= (1 << i);
        } else {
            // no input in that bucket
            d[i]        = NULL;
            byteLens[i] = 0;
        }
    }

    transform_4sb_to_mb4((U64*)out_mb4, bitLen, (const int8u**)d, byteLens, RADIX_CVT);

    return retVal;
}
#endif /* BN_OPENSSL_DISABLE */

// Simlilar to ifma_BN_to_mb4(), but converts array of int64u instead of BIGNUM
// Assumed that each converted values has bitLen length
int8u ifma_BNU_to_mb4(int64u out_mb4[][4], const int64u* const bn[4], int bitLen)
{
    // Check input parameters
    assert(bitLen > 0);

    int byteLens[4];
    int byteLen  = NUMBER_OF_DIGITS(bitLen, 8);
    int8u retVal = 0;
    int i;

    for (i = 0; i < 4; ++i) {
        if (NULL != bn[i]) {
            byteLens[i] = byteLen;
            retVal |= (1 << i);
        } else {
            byteLens[i] = 0;
        }
    }

    transform_4sb_to_mb4((U64*)out_mb4, bitLen, (const int8u**)bn, byteLens, RADIX_CVT);

    return retVal;
}

int8u ifma_HexStr4_to_mb4(int64u out_mb4[][4], const int8u* const pStr[4], int bitLen)
{
    // check input parameters
    assert(bitLen > 0);

    int byteLens[4];
    int byteLen = NUMBER_OF_DIGITS(bitLen, 8);
    int i;
    int8u retVal = 0;

    for (i = 0; i < 4; i++) {
        if (NULL != pStr[i]) {
            byteLens[i] = byteLen;
            retVal |= (1 << i);
        } else {
            byteLens[i] = 0;
        }
    }

    transform_4sb_to_mb4(
        (U64*)out_mb4, bitLen, (const int8u**)pStr, byteLens, RADIX_CVT | BYTES_REV);

    return retVal;
}
////////////////////////////////////////////////////////////////////////////////////////////////////

/*
// transpose MB into 4 SB including (reverse bytes and) radix 2^52 => 2^64 conversion
//
// covers:
//    - mb4 -> 4 BNU
//    - mb4 -> 4 hex strings
*/
__MBX_INLINE void transform_mb4_to_4sb(int8u* out[4],
                                       int outLen[4],
                                       const U64 inp_mb4[],
                                       const int bitLen,
                                       const int flag)
{
    const int bytesRev = flag & BYTES_REV; /* reverse flag */
    const int radixCvt = flag & RADIX_CVT; /* radix (52->64) conversion assumed */

    int inpDigits               = NUMBER_OF_DIGITS(bitLen, DIGIT_SIZE); /* digits */
    int outBytes                = NUMBER_OF_DIGITS(bitLen, 8);          /* bytes */
    const __m256i* inp_mb4_simd = (const __m256i*)inp_mb4;

    for (int i = 0; outBytes > 0; i += PROC_LEN2, outBytes -= PROC_LEN2, inp_mb4_simd += 4) {
        __m256i X[4] = {};

        /*
         * Load & transpose. Initial layout:
         *
         * A0 B0 C0 D0
         * A1 B1 C1 D1
         * A2 B2 C2 D2
         * A3 B3 C3 D3
         */

        for (int n = 0; (n < 4) && (inpDigits > 0); n++, inpDigits--)
            X[n] = _mm256_loadu_si256((const __m256i*)&inp_mb4_simd[n]);

        /*
         * X[0] = A0 B0 C0 D0
         * X[1] = A1 B1 C1 D1
         * X[2] = A2 B2 C2 D2
         * X[3] = A3 B3 C3 D3
         */

        transpose_4x64bx4(&X[0], &X[1], &X[2], &X[3]);

        /*
         * X[0] = A0 A1 A2 A3
         * X[1] = B0 B1 B2 B3
         * X[2] = C0 C1 C2 C3
         * X[3] = D0 D1 D2 D3
         */

        if (radixCvt) {
            // convert 4 x 64 bit words spread across X[i] into
            // consecutive 4 x 52 bit words:

            // shift left
            const __m256i shiftLeft = _mm256_set_epi64x(4, 0, 4, 0);
            // radix 2^52 mask of digits
            const __m256i mask52b = _mm256_set_epi64x(0, DIGIT_MASK, 0, DIGIT_MASK);
            // repeat one byte
            /* clang-format off */
            const __m256i shift_2nd_52b =
                    _mm256_set_epi8(0xff, 0xff, 0xff, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a,
                                    0x09, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a,
                                    0x09, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
            /* clang-format on */

            for (int n = 0; n < 4; n++) {
                const __m256i a0 = _mm256_sllv_epi64(X[n], shiftLeft);
                const __m256i b0 = _mm256_shuffle_epi8(a0, shift_2nd_52b);
                const __m256i c0 = _mm256_and_si256(a0, mask52b);
                const __m256i d0 = _mm256_or_si256(b0, c0);

                const __m128i l0 = _mm256_castsi256_si128(d0);
                const __m128i l1 = _mm256_extracti128_si256(d0, 1);

                /* m0 = l1[2..0] | l0 */
                const __m128i m0 = _mm_alignr_epi8(l1, _mm_bslli_si128(l0, 3), 3);
                /* m1 = ZERO | l1[12..3] */
                const __m128i m1 = _mm_alignr_epi8(_mm_setzero_si128(), _mm_bslli_si128(l1, 3), 6);

                X[n] = _mm256_inserti128_si256(_mm256_castsi128_si256(m0), m1, 1);
            }
        }

        // store transposed digits
        if (bytesRev) {
            for (int n = 0; n < 4; n++) {
                const int L1 = outLen[n] - i;

                if (L1 <= 0)
                    continue;

                const int L2    = (L1 > PROC_LEN2) ? PROC_LEN2 : L1;
                const int sbidx = outBytes - L2;
                int8u* ptr      = out[n] + sbidx;

                // inverse bytes (reverse=1)
                const __m256i swap_mask = _mm256_set_epi64x(
                    0x0001020304050607, 0x08090a0b0c0d0e0f, 0x0001020304050607, 0x08090a0b0c0d0e0f);

                const __m256i t256ab = _mm256_shuffle_epi8(X[n], swap_mask);
                const __m256i t256ba = _mm256_permute4x64_epi64(t256ab, 0x4e);

                X[n] = t256ba;

                if (L2 == PROC_LEN) {
                    _mm_storeu_si128((__m128i*)&ptr[0], _mm256_castsi256_si128(X[n]));
                    *((int64u*)&ptr[16]) = _mm256_extract_epi64(X[n], 2);
                    *((int16u*)&ptr[24]) = _mm256_extract_epi16(X[n], 12);
                } else {
                    union {
                        int8u buffer[32];
                        __m256i x256;
                    } u;

                    u.x256 = X[n];
                    CopyBlock(&u.buffer[32 - L2], ptr, L2);
                }
            }
        } else {
            const int sbidx = i;

            for (int n = 0; n < 4; n++) {
                const int L1 = outLen[n] - i;

                if (L1 <= 0)
                    continue;

                const int L2 = L1 > PROC_LEN2 ? PROC_LEN2 : L1;
                int8u* ptr   = out[n] + sbidx;

                if (L2 == PROC_LEN2) {
                    _mm_storeu_si128((__m128i*)&ptr[0], _mm256_castsi256_si128(X[n]));
                    *((int64u*)&ptr[16]) = _mm256_extract_epi64(X[n], 2);
                    *((int16u*)&ptr[24]) = _mm256_extract_epi16(X[n], 12);
                } else {
                    union {
                        int8u buffer[32];
                        __m256i x256;
                    } u;

                    u.x256 = X[n];
                    CopyBlock(&u.buffer[0], ptr, L2);
                }
            }
        } // bytesRev
    }
}

int8u ifma_mb4_to_BNU(int64u* const out_bn[4], const int64u inp_mb4[][4], const int bitLen)
{
    // Check input parameters
    assert(bitLen > 0);

    const int bnu_bitlen = NUMBER_OF_DIGITS(bitLen, 64) * 64; // gres: output length is multiple 64
    int byteLens[4];
    int8u retVal = 0;
    int i;

    for (i = 0; i < 4; ++i) {
        if (NULL != out_bn[i]) {
            byteLens[i] = NUMBER_OF_DIGITS(bnu_bitlen, 8);
            retVal |= (1 << i);
        } else {
            byteLens[i] = 0;
        }
    }

    transform_mb4_to_4sb((int8u**)out_bn, byteLens, (U64*)inp_mb4, bitLen, RADIX_CVT);
    return retVal;
}

int8u ifma_mb4_to_HexStr4(int8u* const pStr[4], const int64u inp_mb4[][4], int bitLen)
{
    // check input parameters
    assert(bitLen > 0);

    int byteLens[4];
    const int byteLen = NUMBER_OF_DIGITS(bitLen, 8);
    int8u retVal      = 0;
    int i;

    for (i = 0; i < 4; i++) {
        if (NULL != pStr[i]) {
            byteLens[i] = byteLen;
            retVal |= (1 << i);
        } else {
            byteLens[i] = 0;
        }
    }

    transform_mb4_to_4sb((int8u**)pStr, byteLens, (U64*)inp_mb4, bitLen, RADIX_CVT | BYTES_REV);

    return retVal;
}
////////////////////////////////////////////////////////////////////////////////////////////////////

/*
// transpose 4 SB into MB without radix conversion
//
// covers:
//    - mb4 -> 8 BNU
//    - mb4 -> 8 hex strings
*/
int8u ifma_BNU_transpose_copy_mb4(int64u out_mb4[][4], const int64u* const bn[4], const int bitLen)
{
    // Check input parameters
    assert(bitLen > 0);

    int8u ret = 0;

    for (int i = 0; i < 4; ++i)
        if (NULL != bn[i])
            ret |= (1 << i);

    int len = NUMBER_OF_DIGITS(bitLen, 64);

    for (int n = 0; len > 0; n += 4, out_mb4 += 4) {
        __m256i X[4];
        const int L1 = (len > 4) ? 4 : len;

        for (int k = 0; k < 4; k++) {
            if (bn[k] == NULL) {
                X[k] = _mm256_setzero_si256();
                continue;
            }

            if (L1 == 4) {
                X[k] = _mm256_loadu_si256((const __m256i*)&bn[k][n]);
                continue;
            }

            const int64u mask[2 * 8] = { 1ULL << 63, 1ULL << 63, 1ULL << 63, 1ULL << 63,
                                         1ULL << 63, 1ULL << 63, 1ULL << 63, 1ULL << 63,
                                         0ULL,       0ULL,       0ULL,       0ULL,
                                         0ULL,       0ULL,       0ULL,       0ULL };
            const __m256i m1         = _mm256_loadu_si256((const __m256i*)&mask[8 - L1]);

            X[k] = _mm256_maskload_epi64((const void*)&bn[k][n], m1);
        }

        /*
         * X[0] = A0 A1 A2 A3
         * X[1] = B0 B1 B2 B3
         * X[2] = C0 C1 C2 C3
         * X[3] = D0 D1 D2 D3
         */

        transpose_4x64bx4(&X[0], &X[1], &X[2], &X[3]);

        /*
         * X[0] = A0 B0 C0 D0
         * X[1] = A1 B1 C1 D1
         * X[2] = A2 B2 C2 D2
         * X[3] = A3 B3 C3 D4
         */

        // store transposed digits
        for (int k = 0; (k < 4) && (len > 0); k++, len--)
            _mm256_storeu_si256((__m256i*)&out_mb4[k], X[k]);
    }

    return ret;
}

#ifndef BN_OPENSSL_DISABLE
int8u ifma_BN_transpose_copy_mb4(int64u out_mb4[][4], const BIGNUM* const bn[4], const int bitLen)
{
    // check input length
    assert((0 < bitLen) && (bitLen <= IFMA_MAX_BITSIZE));

    int8u ret = 0;
    int64u* inp[4];
#ifndef BN_OPENSSL_PATCH
    __ALIGN64 int64u buffer[4][NUMBER_OF_DIGITS(IFMA_MAX_BITSIZE, 64)];
#endif

    for (int i = 0; i < 4; ++i) {
        if (NULL == bn[i]) {
            inp[i] = NULL;
        } else {
            ret |= (1 << i);

#ifndef BN_OPENSSL_PATCH
            const int byteLen = NUMBER_OF_DIGITS(bitLen, 64) * 8;

            inp[i] = buffer[i];
            BN_bn2lebinpad(bn[i], (unsigned char*)inp[i], byteLen);
#else
            inp[i] = (int64u*)bn_get_words(bn[i]);
#endif
        }
    }

    int len = NUMBER_OF_DIGITS(bitLen, 64);

    for (int n = 0; len > 0; n += 4, out_mb4 += 4) {
        __m256i X[4];
        const int L1 = (len > 4) ? 4 : len;

        for (int k = 0; k < 4; k++) {
            if (inp[k] == NULL) {
                X[k] = _mm256_setzero_si256();
                continue;
            }

            if (L1 == 4) {
                X[k] = _mm256_loadu_si256((const __m256i*)&inp[k][n]);
                continue;
            }

            const int64u mask[2 * 8] = { 1ULL << 63, 1ULL << 63, 1ULL << 63, 1ULL << 63,
                                         1ULL << 63, 1ULL << 63, 1ULL << 63, 1ULL << 63,
                                         0ULL,       0ULL,       0ULL,       0ULL,
                                         0ULL,       0ULL,       0ULL,       0ULL };
            const __m256i m1         = _mm256_loadu_si256((const __m256i*)&mask[8 - L1]);

            X[k] = _mm256_maskload_epi64((const void*)&inp[k][n], m1);
        }

        /*
         * X[0] = A0 A1 A2 A3
         * X[1] = B0 B1 B2 B3
         * X[2] = C0 C1 C2 C3
         * X[3] = D0 D1 D2 D3
         */

        transpose_4x64bx4(&X[0], &X[1], &X[2], &X[3]);

        /*
         * X[0] = A0 B0 C0 D0
         * X[1] = A1 B1 C1 D1
         * X[2] = A2 B2 C2 D2
         * X[3] = A3 B3 C3 D4
         */

        // store transposed digits
        for (int k = 0; (k < 4) && (len > 0); k++, len--)
            _mm256_storeu_si256((__m256i*)&out_mb4[k], X[k]);
    }

    return ret;
}
#endif /* BN_OPENSSL_DISABLE */

#endif /* #if (_MBX >= _MBX_K1) */
