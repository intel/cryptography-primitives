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
#include <internal/common/ifma_math.h>

#if (_MBX >= _MBX_K1)

void AMS5x52x3_diagonal_mb8(int64u* out_mb,
                            const int64u* inpA_mb,
                            const int64u* inpM_mb,
                            const int64u* k0_mb)
{
    U64 res0, res1, res2, res3, res4, res5;
    U64 k;
    U64* a = (U64*)inpA_mb;
    U64* m = (U64*)inpM_mb;
    U64* r = (U64*)out_mb;
    int iter;
    const int iters = 5;

    k = loadu64((U64*)k0_mb);
    for (iter = 0; iter < iters; ++iter) {
        res0 = res1 = res2 = res3 = res4 = res5 = get_zero64();
        // Calculate full square
        res1 = fma52lo(res1, a[0], a[1]); // Sum(1)
        res2 = fma52hi(res2, a[0], a[1]); // Sum(1)
        res2 = fma52lo(res2, a[0], a[2]); // Sum(2)
        res3 = fma52hi(res3, a[0], a[2]); // Sum(2)
        res3 = fma52lo(res3, a[1], a[2]); // Sum(3)
        res4 = fma52hi(res4, a[1], a[2]); // Sum(3)
        res0 = add64(res0, res0);         // Double(0)
        res1 = add64(res1, res1);         // Double(1)
        res2 = add64(res2, res2);         // Double(2)
        res3 = add64(res3, res3);         // Double(3)
        res4 = add64(res4, res4);         // Double(4)
        res0 = fma52lo(res0, a[0], a[0]); // Add sqr(0)
        res1 = fma52hi(res1, a[0], a[0]); // Add sqr(0)
        res2 = fma52lo(res2, a[1], a[1]); // Add sqr(2)
        res3 = fma52hi(res3, a[1], a[1]); // Add sqr(2)
        res4 = fma52lo(res4, a[2], a[2]); // Add sqr(4)
        res5 = fma52hi(res5, a[2], a[2]); // Add sqr(4)

        // Generate u_i
        U64 u0 = mul52lo(res0, k);
        ASM("jmp l0\nl0:\n");

        // Create u0
        fma52lo_mem(res0, res0, u0, m, SIMD_BYTES * 0);
        fma52hi_mem(res1, res1, u0, m, SIMD_BYTES * 0);
        res1   = fma52lo(res1, u0, m[1]);
        res2   = fma52hi(res2, u0, m[1]);
        res1   = add64(res1, srli64(res0, DIGIT_SIZE));
        U64 u1 = mul52lo(res1, k);
        fma52lo_mem(res2, res2, u0, m, SIMD_BYTES * 2);
        fma52hi_mem(res3, res3, u0, m, SIMD_BYTES * 2);

        // Create u1
        fma52lo_mem(res1, res1, u1, m, SIMD_BYTES * 0);
        fma52hi_mem(res2, res2, u1, m, SIMD_BYTES * 0);
        res2   = fma52lo(res2, u1, m[1]);
        res3   = fma52hi(res3, u1, m[1]);
        res2   = add64(res2, srli64(res1, DIGIT_SIZE));
        U64 u2 = mul52lo(res2, k);
        fma52lo_mem(res3, res3, u1, m, SIMD_BYTES * 2);
        fma52hi_mem(res4, res4, u1, m, SIMD_BYTES * 2);
        ASM("jmp l2\nl2:\n");

        // Create u2
        fma52lo_mem(res2, res2, u2, m, SIMD_BYTES * 0);
        fma52hi_mem(res3, res3, u2, m, SIMD_BYTES * 0);
        res3 = fma52lo(res3, u2, m[1]);
        res4 = fma52hi(res4, u2, m[1]);
        res3 = add64(res3, srli64(res2, DIGIT_SIZE));
        fma52lo_mem(res4, res4, u2, m, SIMD_BYTES * 2);
        fma52hi_mem(res5, res5, u2, m, SIMD_BYTES * 2);

        // Normalization
        r[0] = res3;
        res4 = add64(res4, srli64(res3, DIGIT_SIZE));
        r[1] = res4;
        res5 = add64(res5, srli64(res4, DIGIT_SIZE));
        r[2] = res5;
        a    = (U64*)out_mb;
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
