/*************************************************************************
 * Copyright (C) 2019-2026 Intel Corporation
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

#if (_MBX >= _MBX_K1)

#include <internal/common/ifma_math.h>

void ifma_amm52x3_mb8(int64u* out_mb,
                      const int64u* inpA_mb,
                      const int64u* inpB_mb,
                      const int64u* inpM_mb,
                      const int64u* k0_mb)
{
    U64 res00, res01, res02;
    U64 K = loadu64(k0_mb);
    int itr;
    res00 = res01 = res02 = get_zero64();

    for (itr = 0; itr < 3; itr++) {
        U64 Yi;
        U64 Bi = loadu64(inpB_mb);
        inpB_mb += MB_WIDTH;
        fma52lo_mem(res00, res00, Bi, inpA_mb, SIMD_BYTES * 0);
        fma52lo_mem(res01, res01, Bi, inpA_mb, SIMD_BYTES * 1);
        fma52lo_mem(res02, res02, Bi, inpA_mb, SIMD_BYTES * 2);
        Yi = fma52lo(get_zero64(), res00, K);
        fma52lo_mem(res00, res00, Yi, inpM_mb, SIMD_BYTES * 0);
        fma52lo_mem(res01, res01, Yi, inpM_mb, SIMD_BYTES * 1);
        fma52lo_mem(res02, res02, Yi, inpM_mb, SIMD_BYTES * 2);
        res00 = srli64(res00, DIGIT_SIZE);
        res01 = add64(res01, res00);
        fma52hi_mem(res00, res01, Bi, inpA_mb, SIMD_BYTES * 0);
        fma52hi_mem(res01, res02, Bi, inpA_mb, SIMD_BYTES * 1);
        fma52hi_mem(res02, get_zero64(), Bi, inpA_mb, SIMD_BYTES * 2);
        fma52hi_mem(res00, res00, Yi, inpM_mb, SIMD_BYTES * 0);
        fma52hi_mem(res01, res01, Yi, inpM_mb, SIMD_BYTES * 1);
        fma52hi_mem(res02, res02, Yi, inpM_mb, SIMD_BYTES * 2);
    }
    // Normalization
    {
        U64 T    = get_zero64();
        U64 MASK = set64(DIGIT_MASK);
        T        = srli64(res00, DIGIT_SIZE);
        res00    = and64(res00, MASK);
        storeu64(out_mb + MB_WIDTH * 0, res00);
        res01 = add64(res01, T);
        T     = srli64(res01, DIGIT_SIZE);
        res01 = and64(res01, MASK);
        storeu64(out_mb + MB_WIDTH * 1, res01);
        res02 = add64(res02, T);
        res02 = and64(res02, MASK);
        storeu64(out_mb + MB_WIDTH * 2, res02);
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
