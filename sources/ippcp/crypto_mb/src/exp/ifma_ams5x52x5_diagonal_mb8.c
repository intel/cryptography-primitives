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

void AMS5x52x5_diagonal_mb8(int64u* out_mb,
                            const int64u* inpA_mb,
                            const int64u* inpM_mb,
                            const int64u* k0_mb)
{
    U64 res0, res1, res2, res3, res4, res5, res6, res7, res8, res9;
    U64 k;
    U64* a = (U64*)inpA_mb;
    U64* m = (U64*)inpM_mb;
    U64* r = (U64*)out_mb;
    int iter;
    const int iters = 5;

    k = loadu64((U64*)k0_mb);
    for (iter = 0; iter < iters; ++iter) {
        res0 = res1 = res2 = res3 = res4 = res5 = res6 = res7 = res8 = res9 = get_zero64();
        // Calculate full square
        res1 = fma52lo(res1, a[0], a[1]); // Sum(1)
        res2 = fma52hi(res2, a[0], a[1]); // Sum(1)
        res2 = fma52lo(res2, a[0], a[2]); // Sum(2)
        res3 = fma52hi(res3, a[0], a[2]); // Sum(2)
        res3 = fma52lo(res3, a[1], a[2]); // Sum(3)
        res4 = fma52hi(res4, a[1], a[2]); // Sum(3)
        res3 = fma52lo(res3, a[0], a[3]); // Sum(3)
        res4 = fma52hi(res4, a[0], a[3]); // Sum(3)
        res4 = fma52lo(res4, a[1], a[3]); // Sum(4)
        res5 = fma52hi(res5, a[1], a[3]); // Sum(4)
        res5 = fma52lo(res5, a[2], a[3]); // Sum(5)
        res6 = fma52hi(res6, a[2], a[3]); // Sum(5)
        res4 = fma52lo(res4, a[0], a[4]); // Sum(4)
        res5 = fma52hi(res5, a[0], a[4]); // Sum(4)
        res5 = fma52lo(res5, a[1], a[4]); // Sum(5)
        res6 = fma52hi(res6, a[1], a[4]); // Sum(5)
        res6 = fma52lo(res6, a[2], a[4]); // Sum(6)
        res7 = fma52hi(res7, a[2], a[4]); // Sum(6)
        res7 = fma52lo(res7, a[3], a[4]); // Sum(7)
        res8 = fma52hi(res8, a[3], a[4]); // Sum(7)
        res0 = add64(res0, res0);         // Double(0)
        res1 = add64(res1, res1);         // Double(1)
        res2 = add64(res2, res2);         // Double(2)
        res3 = add64(res3, res3);         // Double(3)
        res4 = add64(res4, res4);         // Double(4)
        res5 = add64(res5, res5);         // Double(5)
        res6 = add64(res6, res6);         // Double(6)
        res7 = add64(res7, res7);         // Double(7)
        res8 = add64(res8, res8);         // Double(8)
        res9 = add64(res9, res9);         // Double(9)
        res0 = fma52lo(res0, a[0], a[0]); // Add sqr(0)
        res1 = fma52hi(res1, a[0], a[0]); // Add sqr(0)
        res2 = fma52lo(res2, a[1], a[1]); // Add sqr(2)
        res3 = fma52hi(res3, a[1], a[1]); // Add sqr(2)
        res4 = fma52lo(res4, a[2], a[2]); // Add sqr(4)
        res5 = fma52hi(res5, a[2], a[2]); // Add sqr(4)
        res6 = fma52lo(res6, a[3], a[3]); // Add sqr(6)
        res7 = fma52hi(res7, a[3], a[3]); // Add sqr(6)
        res8 = fma52lo(res8, a[4], a[4]); // Add sqr(8)
        res9 = fma52hi(res9, a[4], a[4]); // Add sqr(8)

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
        res3 = fma52lo(res3, u0, m[3]);
        res4 = fma52hi(res4, u0, m[3]);
        fma52lo_mem(res4, res4, u0, m, SIMD_BYTES * 4);
        fma52hi_mem(res5, res5, u0, m, SIMD_BYTES * 4);

        // Create u1
        fma52lo_mem(res1, res1, u1, m, SIMD_BYTES * 0);
        fma52hi_mem(res2, res2, u1, m, SIMD_BYTES * 0);
        res2   = fma52lo(res2, u1, m[1]);
        res3   = fma52hi(res3, u1, m[1]);
        res2   = add64(res2, srli64(res1, DIGIT_SIZE));
        U64 u2 = mul52lo(res2, k);
        fma52lo_mem(res3, res3, u1, m, SIMD_BYTES * 2);
        fma52hi_mem(res4, res4, u1, m, SIMD_BYTES * 2);
        res4 = fma52lo(res4, u1, m[3]);
        res5 = fma52hi(res5, u1, m[3]);
        fma52lo_mem(res5, res5, u1, m, SIMD_BYTES * 4);
        fma52hi_mem(res6, res6, u1, m, SIMD_BYTES * 4);
        ASM("jmp l2\nl2:\n");

        // Create u2
        fma52lo_mem(res2, res2, u2, m, SIMD_BYTES * 0);
        fma52hi_mem(res3, res3, u2, m, SIMD_BYTES * 0);
        res3   = fma52lo(res3, u2, m[1]);
        res4   = fma52hi(res4, u2, m[1]);
        res3   = add64(res3, srli64(res2, DIGIT_SIZE));
        U64 u3 = mul52lo(res3, k);
        fma52lo_mem(res4, res4, u2, m, SIMD_BYTES * 2);
        fma52hi_mem(res5, res5, u2, m, SIMD_BYTES * 2);
        res5 = fma52lo(res5, u2, m[3]);
        res6 = fma52hi(res6, u2, m[3]);
        fma52lo_mem(res6, res6, u2, m, SIMD_BYTES * 4);
        fma52hi_mem(res7, res7, u2, m, SIMD_BYTES * 4);

        // Create u3
        fma52lo_mem(res3, res3, u3, m, SIMD_BYTES * 0);
        fma52hi_mem(res4, res4, u3, m, SIMD_BYTES * 0);
        res4   = fma52lo(res4, u3, m[1]);
        res5   = fma52hi(res5, u3, m[1]);
        res4   = add64(res4, srli64(res3, DIGIT_SIZE));
        U64 u4 = mul52lo(res4, k);
        fma52lo_mem(res5, res5, u3, m, SIMD_BYTES * 2);
        fma52hi_mem(res6, res6, u3, m, SIMD_BYTES * 2);
        res6 = fma52lo(res6, u3, m[3]);
        res7 = fma52hi(res7, u3, m[3]);
        fma52lo_mem(res7, res7, u3, m, SIMD_BYTES * 4);
        fma52hi_mem(res8, res8, u3, m, SIMD_BYTES * 4);
        ASM("jmp l4\nl4:\n");

        // Create u4
        fma52lo_mem(res4, res4, u4, m, SIMD_BYTES * 0);
        fma52hi_mem(res5, res5, u4, m, SIMD_BYTES * 0);
        res5 = fma52lo(res5, u4, m[1]);
        res6 = fma52hi(res6, u4, m[1]);
        res5 = add64(res5, srli64(res4, DIGIT_SIZE));
        //U64 u5 = mul52lo(res5, k);
        fma52lo_mem(res6, res6, u4, m, SIMD_BYTES * 2);
        fma52hi_mem(res7, res7, u4, m, SIMD_BYTES * 2);
        res7 = fma52lo(res7, u4, m[3]);
        res8 = fma52hi(res8, u4, m[3]);
        fma52lo_mem(res8, res8, u4, m, SIMD_BYTES * 4);
        fma52hi_mem(res9, res9, u4, m, SIMD_BYTES * 4);

        // Normalization
        r[0] = res5;
        res6 = add64(res6, srli64(res5, DIGIT_SIZE));
        r[1] = res6;
        res7 = add64(res7, srli64(res6, DIGIT_SIZE));
        r[2] = res7;
        res8 = add64(res8, srli64(res7, DIGIT_SIZE));
        r[3] = res8;
        res9 = add64(res9, srli64(res8, DIGIT_SIZE));
        r[4] = res9;
        a    = (U64*)out_mb;
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
