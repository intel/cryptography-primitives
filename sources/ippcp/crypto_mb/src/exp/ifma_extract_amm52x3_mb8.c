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

void ifma_extract_amm52x3_mb8(int64u* out_mb8,
                              const int64u* inpA_mb8,
                              int64u MulTbl[][redLen256][8],
                              const int64u Idx[8],
                              const int64u* inpM_mb8,
                              const int64u* k0_mb8)
{
    U64 res00, res01, res02;
    U64 mulB00, mulB01, mulB02;
    U64 K = loadu64(k0_mb8); /* k0[] */
    __mmask8 k;
    __ALIGN64 U64 inpB_mb8[3];
    int itr;
    res00 = res01 = res02 = get_zero64();

    U64 idx_target = loadu64((U64*)Idx);
    k              = cmpeq64_mask(set64(1), idx_target);
    mulB00         = loadu64(MulTbl[0][0]);
    mulB01         = loadu64(MulTbl[0][1]);
    mulB02         = loadu64(MulTbl[0][2]);
    for (itr = 1; itr < (1 << 5); ++itr) {
        U64 idx_curr   = set64(itr + 1);
        __mmask8 k_new = cmpeq64_mask(idx_curr, idx_target);
        mulB00         = select64(k, mulB00, (U64*)MulTbl[itr][0]);
        mulB01         = select64(k, mulB01, (U64*)MulTbl[itr][1]);
        mulB02         = select64(k, mulB02, (U64*)MulTbl[itr][2]);
        k              = k_new;
    }
    inpB_mb8[0] = mulB00;
    inpB_mb8[1] = mulB01;
    inpB_mb8[2] = mulB02;

    for (itr = 0; itr < 3; itr++) {
        U64 Yi;
        U64 Bi = inpB_mb8[itr];
        fma52lo_mem(res00, res00, Bi, inpA_mb8, 64 * 0);
        fma52lo_mem(res01, res01, Bi, inpA_mb8, 64 * 1);
        fma52lo_mem(res02, res02, Bi, inpA_mb8, 64 * 2);
        Yi = fma52lo(get_zero64(), res00, K);
        fma52lo_mem(res00, res00, Yi, inpM_mb8, 64 * 0);
        fma52lo_mem(res01, res01, Yi, inpM_mb8, 64 * 1);
        fma52lo_mem(res02, res02, Yi, inpM_mb8, 64 * 2);
        res00 = srli64(res00, DIGIT_SIZE);
        res01 = add64(res01, res00);
        fma52hi_mem(res00, res01, Bi, inpA_mb8, 64 * 0);
        fma52hi_mem(res01, res02, Bi, inpA_mb8, 64 * 1);
        fma52hi_mem(res02, get_zero64(), Bi, inpA_mb8, 64 * 2);
        fma52hi_mem(res00, res00, Yi, inpM_mb8, 64 * 0);
        fma52hi_mem(res01, res01, Yi, inpM_mb8, 64 * 1);
        fma52hi_mem(res02, res02, Yi, inpM_mb8, 64 * 2);
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
        storeu64(out_mb8 + 8 * 2, res02);
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
