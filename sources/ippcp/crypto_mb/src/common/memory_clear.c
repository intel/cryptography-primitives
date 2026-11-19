/*************************************************************************
 * Copyright (C) 2025 Intel Corporation
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
#include <internal/common/memory_clear.h>

#if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED))

#if defined(_MSC_VER) && !defined(__clang__)
#pragma optimize("", off)
#endif

/*
 * One implementation for both builds: U64 is __m512i in the k1 build (zero_mb8)
 * and __m256i in the l9 build (zero_mb4). Only the tail shorter than one vector differs.
 * The tail is not a plain byte loop: the compiler vectorizes such a loop, which makes
 * the function several times larger.
 */
__NOINLINE
void MB_FUNC_NAME(zero_)(void* out, int len)
{
    const U64 T = get_zero64();
    int8u* p    = (int8u*)out;
    int i       = 0;

    for (; i <= len - (int)sizeof(U64); i += (int)sizeof(U64))
        storeu64(p + i, T);

#if (SIMD_LEN == 512)
    /* tail: one masked store; the bytes that are masked out are not accessed */
    if (i < len)
        _mm512_mask_storeu_epi8(p + i, (__mmask64)(((int64u)1 << (len - i)) - 1), T);
#else
    /* tail: AVX2 has no byte-masked store; volatile byte stores are not vectorized */
    for (; i < len; i++)
        ((volatile int8u*)p)[i] = 0;
#endif

#if defined(__GNUC__) || defined(__clang__)
    /*
     * Compiler barrier: the buffer is treated as read here, so the stores above
     * cannot be removed as dead stores, also under link-time optimization.
     */
    __asm__ __volatile__("" : : "r"(out) : "memory");
#endif
}

#if defined(_MSC_VER) && !defined(__clang__)
#pragma optimize("", on)
#endif

#endif /* #if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)) */
