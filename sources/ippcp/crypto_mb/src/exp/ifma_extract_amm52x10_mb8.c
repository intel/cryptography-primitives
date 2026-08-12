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
#include <internal/rsa/ifma_rsa_arith.h>

#if (_MBX >= _MBX_K1)

void ifma_extract_amm52x10_mb8(int64u* out_mb8,
                               const int64u* inpA_mb8,
                               int64u MulTbl[][redLen1K][8],
                               const int64u Idx[8],
                               const int64u* inpM_mb8,
                               const int64u* k0_mb8)
{
    U64 res00, res01, res02, res03, res04, res05, res06, res07, res08, res09;
    U64 mulB00, mulB01, mulB02, mulB03, mulB04, mulB05, mulB06, mulB07, mulB08, mulB09;
    U64 K = loadu64(k0_mb8); /* k0[] */
    __mmask8 k;
    __ALIGN64 U64 inpB_mb8[10];
    int itr;
    res00 = res01 = res02 = res03 = res04 = res05 = res06 = res07 = res08 = res09 = get_zero64();

    U64 idx_target = loadu64((U64*)Idx);
    k              = cmpeq64_mask(set64(1), idx_target);
    mulB00         = loadu64(MulTbl[0][0]);
    mulB01         = loadu64(MulTbl[0][1]);
    mulB02         = loadu64(MulTbl[0][2]);
    mulB03         = loadu64(MulTbl[0][3]);
    mulB04         = loadu64(MulTbl[0][4]);
    mulB05         = loadu64(MulTbl[0][5]);
    mulB06         = loadu64(MulTbl[0][6]);
    mulB07         = loadu64(MulTbl[0][7]);
    mulB08         = loadu64(MulTbl[0][8]);
    mulB09         = loadu64(MulTbl[0][9]);
    for (itr = 1; itr < (1 << 5); ++itr) {
        U64 idx_curr   = set64(itr + 1);
        __mmask8 k_new = cmpeq64_mask(idx_curr, idx_target);
        mulB00         = select64(k, mulB00, (U64*)MulTbl[itr][0]);
        mulB01         = select64(k, mulB01, (U64*)MulTbl[itr][1]);
        mulB02         = select64(k, mulB02, (U64*)MulTbl[itr][2]);
        mulB03         = select64(k, mulB03, (U64*)MulTbl[itr][3]);
        mulB04         = select64(k, mulB04, (U64*)MulTbl[itr][4]);
        mulB05         = select64(k, mulB05, (U64*)MulTbl[itr][5]);
        mulB06         = select64(k, mulB06, (U64*)MulTbl[itr][6]);
        mulB07         = select64(k, mulB07, (U64*)MulTbl[itr][7]);
        mulB08         = select64(k, mulB08, (U64*)MulTbl[itr][8]);
        mulB09         = select64(k, mulB09, (U64*)MulTbl[itr][9]);
        k              = k_new;
    }
    inpB_mb8[0] = mulB00;
    inpB_mb8[1] = mulB01;
    inpB_mb8[2] = mulB02;
    inpB_mb8[3] = mulB03;
    inpB_mb8[4] = mulB04;
    inpB_mb8[5] = mulB05;
    inpB_mb8[6] = mulB06;
    inpB_mb8[7] = mulB07;
    inpB_mb8[8] = mulB08;
    inpB_mb8[9] = mulB09;

    for (itr = 0; itr < 10; itr++) {
        U64 Yi;
        U64 Bi = inpB_mb8[itr];
        fma52lo_mem(res00, res00, Bi, inpA_mb8, 64 * 0);
        fma52lo_mem(res01, res01, Bi, inpA_mb8, 64 * 1);
        fma52lo_mem(res02, res02, Bi, inpA_mb8, 64 * 2);
        fma52lo_mem(res03, res03, Bi, inpA_mb8, 64 * 3);
        fma52lo_mem(res04, res04, Bi, inpA_mb8, 64 * 4);
        fma52lo_mem(res05, res05, Bi, inpA_mb8, 64 * 5);
        fma52lo_mem(res06, res06, Bi, inpA_mb8, 64 * 6);
        fma52lo_mem(res07, res07, Bi, inpA_mb8, 64 * 7);
        fma52lo_mem(res08, res08, Bi, inpA_mb8, 64 * 8);
        fma52lo_mem(res09, res09, Bi, inpA_mb8, 64 * 9);
        Yi = fma52lo(get_zero64(), res00, K);
        fma52lo_mem(res00, res00, Yi, inpM_mb8, 64 * 0);
        fma52lo_mem(res01, res01, Yi, inpM_mb8, 64 * 1);
        fma52lo_mem(res02, res02, Yi, inpM_mb8, 64 * 2);
        fma52lo_mem(res03, res03, Yi, inpM_mb8, 64 * 3);
        fma52lo_mem(res04, res04, Yi, inpM_mb8, 64 * 4);
        fma52lo_mem(res05, res05, Yi, inpM_mb8, 64 * 5);
        fma52lo_mem(res06, res06, Yi, inpM_mb8, 64 * 6);
        fma52lo_mem(res07, res07, Yi, inpM_mb8, 64 * 7);
        fma52lo_mem(res08, res08, Yi, inpM_mb8, 64 * 8);
        fma52lo_mem(res09, res09, Yi, inpM_mb8, 64 * 9);
        res00 = srli64(res00, DIGIT_SIZE);
        res01 = add64(res01, res00);
        fma52hi_mem(res00, res01, Bi, inpA_mb8, 64 * 0);
        fma52hi_mem(res01, res02, Bi, inpA_mb8, 64 * 1);
        fma52hi_mem(res02, res03, Bi, inpA_mb8, 64 * 2);
        fma52hi_mem(res03, res04, Bi, inpA_mb8, 64 * 3);
        fma52hi_mem(res04, res05, Bi, inpA_mb8, 64 * 4);
        fma52hi_mem(res05, res06, Bi, inpA_mb8, 64 * 5);
        fma52hi_mem(res06, res07, Bi, inpA_mb8, 64 * 6);
        fma52hi_mem(res07, res08, Bi, inpA_mb8, 64 * 7);
        fma52hi_mem(res08, res09, Bi, inpA_mb8, 64 * 8);
        fma52hi_mem(res09, get_zero64(), Bi, inpA_mb8, 64 * 9);
        fma52hi_mem(res00, res00, Yi, inpM_mb8, 64 * 0);
        fma52hi_mem(res01, res01, Yi, inpM_mb8, 64 * 1);
        fma52hi_mem(res02, res02, Yi, inpM_mb8, 64 * 2);
        fma52hi_mem(res03, res03, Yi, inpM_mb8, 64 * 3);
        fma52hi_mem(res04, res04, Yi, inpM_mb8, 64 * 4);
        fma52hi_mem(res05, res05, Yi, inpM_mb8, 64 * 5);
        fma52hi_mem(res06, res06, Yi, inpM_mb8, 64 * 6);
        fma52hi_mem(res07, res07, Yi, inpM_mb8, 64 * 7);
        fma52hi_mem(res08, res08, Yi, inpM_mb8, 64 * 8);
        fma52hi_mem(res09, res09, Yi, inpM_mb8, 64 * 9);
    }
    // Normalization
    {
        U64 T = get_zero64();
        // U64 MASK = set64(DIGIT_MASK);
        T = srli64(res00, DIGIT_SIZE);
        storeu64(out_mb8 + 8 * 0, res00);
        res01 = add64(res01, T);
        T     = srli64(res01, DIGIT_SIZE);
        storeu64(out_mb8 + 8 * 1, res01);
        res02 = add64(res02, T);
        T     = srli64(res02, DIGIT_SIZE);
        storeu64(out_mb8 + 8 * 2, res02);
        res03 = add64(res03, T);
        T     = srli64(res03, DIGIT_SIZE);
        storeu64(out_mb8 + 8 * 3, res03);
        res04 = add64(res04, T);
        T     = srli64(res04, DIGIT_SIZE);
        storeu64(out_mb8 + 8 * 4, res04);
        res05 = add64(res05, T);
        T     = srli64(res05, DIGIT_SIZE);
        storeu64(out_mb8 + 8 * 5, res05);
        res06 = add64(res06, T);
        T     = srli64(res06, DIGIT_SIZE);
        storeu64(out_mb8 + 8 * 6, res06);
        res07 = add64(res07, T);
        T     = srli64(res07, DIGIT_SIZE);
        storeu64(out_mb8 + 8 * 7, res07);
        res08 = add64(res08, T);
        T     = srli64(res08, DIGIT_SIZE);
        storeu64(out_mb8 + 8 * 8, res08);
        res09 = add64(res09, T);
        storeu64(out_mb8 + 8 * 9, res09);
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
