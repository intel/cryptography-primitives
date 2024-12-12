/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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

#if !defined(_SM3_COMMON_H)
#define _SM3_COMMON_H

#include <internal/common/ifma_defs.h>

#include <crypto_mb/defs.h>
#include <crypto_mb/sm3.h>

#include <immintrin.h>

#if (_MBX >= _MBX_K1)

/* size of processed message length representation (bytes) */
#define SM3_MSG_LEN_REPR (sizeof(int64u))

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/*
// accessors to context's fields
*/

#define MSG_LEN(ctx)      ((ctx)->msg_len)
#define HASH_VALUE(ctx)   ((ctx)->msg_hash)
#define HASH_BUFFIDX(ctx) ((ctx)->msg_buff_idx)
#define HASH_BUFF(ctx)    ((ctx)->msg_buffer)

/*
// constants
*/

static const int32u sm3_iv[] = { 0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
                                 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E };

__ALIGN64 static const int8u swapBytes[] = { 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
                                             7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
                                             7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
                                             7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8 };

__ALIGN64 static const int32u tj_calculated[] = {
    0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB, 0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
    0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE, 0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
    0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
    0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
    0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53, 0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
    0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4, 0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43
};

/*
// internal functions
*/


__MBX_INLINE void pad_block(int8u padding_byte, void* dst_p, int num_bytes)
{
    int8u* d = (int8u*)dst_p;
    int k;
    for (k = 0; k < num_bytes; k++)
        d[k] = padding_byte;
}

__MBX_INLINE void TRANSPOSE_8X8_I32(__m256i* v0,
                                    __m256i* v1,
                                    __m256i* v2,
                                    __m256i* v3,
                                    __m256i* v4,
                                    __m256i* v5,
                                    __m256i* v6,
                                    __m256i* v7)
{
    __m256i w0, w1, w2, w3, w4, w5, w6, w7;
    __m256i x0, x1, x2, x3, x4, x5, x6, x7;
    __m256i t1, t2;

    x0 = _mm256_permute4x64_epi64(*v0, 0b11011000);
    x1 = _mm256_permute4x64_epi64(*v1, 0b11011000);
    w0 = _mm256_unpacklo_epi32(x0, x1);
    w1 = _mm256_unpackhi_epi32(x0, x1);

    x2 = _mm256_permute4x64_epi64(*v2, 0b11011000);
    x3 = _mm256_permute4x64_epi64(*v3, 0b11011000);
    w2 = _mm256_unpacklo_epi32(x2, x3);
    w3 = _mm256_unpackhi_epi32(x2, x3);

    x4 = _mm256_permute4x64_epi64(*v4, 0b11011000);
    x5 = _mm256_permute4x64_epi64(*v5, 0b11011000);
    w4 = _mm256_unpacklo_epi32(x4, x5);
    w5 = _mm256_unpackhi_epi32(x4, x5);

    x6 = _mm256_permute4x64_epi64(*v6, 0b11011000);
    x7 = _mm256_permute4x64_epi64(*v7, 0b11011000);
    w6 = _mm256_unpacklo_epi32(x6, x7);
    w7 = _mm256_unpackhi_epi32(x6, x7);

    t1 = _mm256_permute4x64_epi64(w0, 0b11011000);
    t2 = _mm256_permute4x64_epi64(w2, 0b11011000);
    x0 = _mm256_unpacklo_epi64(t1, t2);
    x1 = _mm256_unpackhi_epi64(t1, t2);

    t1 = _mm256_permute4x64_epi64(w1, 0b11011000);
    t2 = _mm256_permute4x64_epi64(w3, 0b11011000);
    x2 = _mm256_unpacklo_epi64(t1, t2);
    x3 = _mm256_unpackhi_epi64(t1, t2);

    t1 = _mm256_permute4x64_epi64(w4, 0b11011000);
    t2 = _mm256_permute4x64_epi64(w6, 0b11011000);
    x4 = _mm256_unpacklo_epi64(t1, t2);
    x5 = _mm256_unpackhi_epi64(t1, t2);

    t1 = _mm256_permute4x64_epi64(w5, 0b11011000);
    t2 = _mm256_permute4x64_epi64(w7, 0b11011000);
    x6 = _mm256_unpacklo_epi64(t1, t2);
    x7 = _mm256_unpackhi_epi64(t1, t2);

    *v0 = _mm256_permute2x128_si256(x0, x4, 0b100000);
    *v1 = _mm256_permute2x128_si256(x0, x4, 0b110001);
    *v2 = _mm256_permute2x128_si256(x1, x5, 0b100000);
    *v3 = _mm256_permute2x128_si256(x1, x5, 0b110001);
    *v4 = _mm256_permute2x128_si256(x2, x6, 0b100000);
    *v5 = _mm256_permute2x128_si256(x2, x6, 0b110001);
    *v6 = _mm256_permute2x128_si256(x3, x7, 0b100000);
    *v7 = _mm256_permute2x128_si256(x3, x7, 0b110001);
}

__MBX_INLINE void MASK_TRANSPOSE_8X8_I32(int32u* out[8],
                                         const int32u* const inp[8],
                                         __mmask16 mb_mask)
{
    __m256i v0 = _mm256_loadu_si256((__m256i*)inp[0]);
    __m256i v1 = _mm256_loadu_si256((__m256i*)inp[1]);
    __m256i v2 = _mm256_loadu_si256((__m256i*)inp[2]);
    __m256i v3 = _mm256_loadu_si256((__m256i*)inp[3]);
    __m256i v4 = _mm256_loadu_si256((__m256i*)inp[4]);
    __m256i v5 = _mm256_loadu_si256((__m256i*)inp[5]);
    __m256i v6 = _mm256_loadu_si256((__m256i*)inp[6]);
    __m256i v7 = _mm256_loadu_si256((__m256i*)inp[7]);

    TRANSPOSE_8X8_I32(&v0, &v1, &v2, &v3, &v4, &v5, &v6, &v7);

    /* mask store hashes to the first 8 buffers */
    _mm256_mask_storeu_epi32((void*)out[0], (__mmask8)(((mb_mask >> 0) & 1)) * 0xFF, v0);
    _mm256_mask_storeu_epi32((void*)out[1], (__mmask8)(((mb_mask >> 1) & 1)) * 0xFF, v1);
    _mm256_mask_storeu_epi32((void*)out[2], (__mmask8)(((mb_mask >> 2) & 1)) * 0xFF, v2);
    _mm256_mask_storeu_epi32((void*)out[3], (__mmask8)(((mb_mask >> 3) & 1)) * 0xFF, v3);
    _mm256_mask_storeu_epi32((void*)out[4], (__mmask8)(((mb_mask >> 4) & 1)) * 0xFF, v4);
    _mm256_mask_storeu_epi32((void*)out[5], (__mmask8)(((mb_mask >> 5) & 1)) * 0xFF, v5);
    _mm256_mask_storeu_epi32((void*)out[6], (__mmask8)(((mb_mask >> 6) & 1)) * 0xFF, v6);
    _mm256_mask_storeu_epi32((void*)out[7], (__mmask8)(((mb_mask >> 7) & 1)) * 0xFF, v7);
}

__MBX_INLINE void TRANSPOSE_8X16_I32(int32u* out[16], const int32u* const inp[8], __mmask16 mb_mask)
{
    __m256i v0 = _mm256_loadu_si256((__m256i*)inp[0]);
    __m256i v1 = _mm256_loadu_si256((__m256i*)inp[1]);
    __m256i v2 = _mm256_loadu_si256((__m256i*)inp[2]);
    __m256i v3 = _mm256_loadu_si256((__m256i*)inp[3]);
    __m256i v4 = _mm256_loadu_si256((__m256i*)inp[4]);
    __m256i v5 = _mm256_loadu_si256((__m256i*)inp[5]);
    __m256i v6 = _mm256_loadu_si256((__m256i*)inp[6]);
    __m256i v7 = _mm256_loadu_si256((__m256i*)inp[7]);

    TRANSPOSE_8X8_I32(&v0, &v1, &v2, &v3, &v4, &v5, &v6, &v7);

    /* mask store hashes to the first 8 buffers */
    _mm256_mask_storeu_epi32((void*)out[0], (__mmask8)(((mb_mask >> 0) & 1)) * 0xFF, v0);
    _mm256_mask_storeu_epi32((void*)out[1], (__mmask8)(((mb_mask >> 1) & 1)) * 0xFF, v1);
    _mm256_mask_storeu_epi32((void*)out[2], (__mmask8)(((mb_mask >> 2) & 1)) * 0xFF, v2);
    _mm256_mask_storeu_epi32((void*)out[3], (__mmask8)(((mb_mask >> 3) & 1)) * 0xFF, v3);
    _mm256_mask_storeu_epi32((void*)out[4], (__mmask8)(((mb_mask >> 4) & 1)) * 0xFF, v4);
    _mm256_mask_storeu_epi32((void*)out[5], (__mmask8)(((mb_mask >> 5) & 1)) * 0xFF, v5);
    _mm256_mask_storeu_epi32((void*)out[6], (__mmask8)(((mb_mask >> 6) & 1)) * 0xFF, v6);
    _mm256_mask_storeu_epi32((void*)out[7], (__mmask8)(((mb_mask >> 7) & 1)) * 0xFF, v7);

    v0 = _mm256_loadu_si256((__m256i*)inp[0] + 1);
    v1 = _mm256_loadu_si256((__m256i*)inp[1] + 1);
    v2 = _mm256_loadu_si256((__m256i*)inp[2] + 1);
    v3 = _mm256_loadu_si256((__m256i*)inp[3] + 1);
    v4 = _mm256_loadu_si256((__m256i*)inp[4] + 1);
    v5 = _mm256_loadu_si256((__m256i*)inp[5] + 1);
    v6 = _mm256_loadu_si256((__m256i*)inp[6] + 1);
    v7 = _mm256_loadu_si256((__m256i*)inp[7] + 1);


    TRANSPOSE_8X8_I32(&v0, &v1, &v2, &v3, &v4, &v5, &v6, &v7);

    /* mask store hashes to the last 8 buffers */
    _mm256_mask_storeu_epi32((void*)out[8], (__mmask8)(((mb_mask >> 8) & 1)) * 0xFF, v0);
    _mm256_mask_storeu_epi32((void*)out[9], (__mmask8)(((mb_mask >> 9) & 1)) * 0xFF, v1);
    _mm256_mask_storeu_epi32((void*)out[10], (__mmask8)(((mb_mask >> 10) & 1)) * 0xFF, v2);
    _mm256_mask_storeu_epi32((void*)out[11], (__mmask8)(((mb_mask >> 11) & 1)) * 0xFF, v3);
    _mm256_mask_storeu_epi32((void*)out[12], (__mmask8)(((mb_mask >> 12) & 1)) * 0xFF, v4);
    _mm256_mask_storeu_epi32((void*)out[13], (__mmask8)(((mb_mask >> 13) & 1)) * 0xFF, v5);
    _mm256_mask_storeu_epi32((void*)out[14], (__mmask8)(((mb_mask >> 14) & 1)) * 0xFF, v6);
    _mm256_mask_storeu_epi32((void*)out[15], (__mmask8)(((mb_mask >> 15) & 1)) * 0xFF, v7);
}

#endif /* #if (_MBX>=_MBX_K1) */

#endif /* _SM3_COMMON_H */
