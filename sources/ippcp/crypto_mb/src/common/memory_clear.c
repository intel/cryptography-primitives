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

#if (_MBX >= _MBX_K1)

__NOINLINE
void zero_mb8(int64u (*out)[8], int len)
{
#if defined(__GNUC__)
    // Avoid dead code elimination for GNU compilers
    ASM("");
#endif
    __m512i T = _mm512_setzero_si512();
    int i;
    for (i = 0; i < len; i++)
        _mm512_storeu_si512(out[i], T);
}

#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

__NOINLINE
void zero_mb4(void* out, int len)
{
#if defined(__GNUC__)
    // Avoid dead code elimination for GNU compilers
    ASM("");
#endif
    const __m256i T = _mm256_setzero_si256();
    __m256i* p_out  = (__m256i*)out;
    int i;

    for (i = 0; i < len; i++)
        _mm256_storeu_si256(p_out++, T);
}

#endif /* #if (_MBX >= _MBX_K1) */
