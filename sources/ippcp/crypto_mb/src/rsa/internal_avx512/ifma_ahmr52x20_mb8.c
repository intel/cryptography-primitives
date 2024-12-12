/*************************************************************************
 * Copyright (C) 2023-2024 Intel Corporation
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

/*
Almost Half Montgomery Reduction (AHMR)

Output:
    out_mb   : C = A*(2^(-10*52)) mod M
Inputs:
    inpA_mb  : A
    inpM_mb  : M
    k0_mb    : mont_constant = (-M^(-1) mod 2^(52))

    C=A
    for i from 0 to 9:
        T=C[0]*mu	// discard T[1]
        C=C+T[0]*M	// C[0] is zero
        C=C>>52		// at each step of the for loop, divide the result by 2^52
    return C
*/

void ifma_ahmr52x20_mb8(int64u* out_mb,
                        const int64u* inpA_mb,
                        const int64u* inpM_mb,
                        const int64u* k0_mb)
{

    U64 res00, res01, res02, res03, res04, res05, res06, res07, res08, res09, res10, res11, res12,
        res13, res14, res15, res16, res17, res18, res19;

    const U64 mont_constant = loadu64(k0_mb);

    res00 = res01 = res02 = res03 = res04 = res05 = res06 = res07 = res08 = res09 = res10 = res11 =
        res12 = res13 = res14 = res15 = res16 = res17 = res18 = res19 = get_zero64();

    // top 12 bits of 64-bit digits of the input A are junk data
    // they need to be masked out before the reduction operation
    const U64 MASK52 = set64(DIGIT_MASK);

    U64* M = (U64*)inpM_mb;

    // C=A
    // res00:res19 are temporary registers holding intermediate result C
    res00 = loadu64(inpA_mb + 0 * MB_WIDTH);
    res00 = and64(res00, MASK52);
    res01 = loadu64(inpA_mb + 1 * MB_WIDTH);
    res01 = and64(res01, MASK52);
    res02 = loadu64(inpA_mb + 2 * MB_WIDTH);
    res02 = and64(res02, MASK52);
    res03 = loadu64(inpA_mb + 3 * MB_WIDTH);
    res03 = and64(res03, MASK52);
    res04 = loadu64(inpA_mb + 4 * MB_WIDTH);
    res04 = and64(res04, MASK52);
    res05 = loadu64(inpA_mb + 5 * MB_WIDTH);
    res05 = and64(res05, MASK52);
    res06 = loadu64(inpA_mb + 6 * MB_WIDTH);
    res06 = and64(res06, MASK52);
    res07 = loadu64(inpA_mb + 7 * MB_WIDTH);
    res07 = and64(res07, MASK52);
    res08 = loadu64(inpA_mb + 8 * MB_WIDTH);
    res08 = and64(res08, MASK52);
    res09 = loadu64(inpA_mb + 9 * MB_WIDTH);
    res09 = and64(res09, MASK52);
    res10 = loadu64(inpA_mb + 10 * MB_WIDTH);
    res10 = and64(res10, MASK52);
    res11 = loadu64(inpA_mb + 11 * MB_WIDTH);
    res11 = and64(res11, MASK52);
    res12 = loadu64(inpA_mb + 12 * MB_WIDTH);
    res12 = and64(res12, MASK52);
    res13 = loadu64(inpA_mb + 13 * MB_WIDTH);
    res13 = and64(res13, MASK52);
    res14 = loadu64(inpA_mb + 14 * MB_WIDTH);
    res14 = and64(res14, MASK52);
    res15 = loadu64(inpA_mb + 15 * MB_WIDTH);
    res15 = and64(res15, MASK52);
    res16 = loadu64(inpA_mb + 16 * MB_WIDTH);
    res16 = and64(res16, MASK52);
    res17 = loadu64(inpA_mb + 17 * MB_WIDTH);
    res17 = and64(res17, MASK52);
    res18 = loadu64(inpA_mb + 18 * MB_WIDTH);
    res18 = and64(res18, MASK52);
    res19 = loadu64(inpA_mb + 19 * MB_WIDTH);
    res19 = and64(res19, MASK52);

    for (int itr = 0; itr < 10; itr++) {
        // T=C[0]*mu
        const U64 T = fma52lo(get_zero64(), res00, mont_constant);

        // C=C+T[0]*M (low part)
        res00 = fma52lo(res00, T, M[0]);

        // low 52 (DIGIT_SIZE) bits of res00 are 0
        // high 12 bits are accumulated to res01 (same bit-weight)
        res00 = srli64(res00, DIGIT_SIZE);
        res01 = add64(res01, res00);

        res01 = fma52lo(res01, T, M[1]);
        res00 = fma52hi(res01, T, M[0]);
        res02 = fma52lo(res02, T, M[2]);
        res01 = fma52hi(res02, T, M[1]);
        res03 = fma52lo(res03, T, M[3]);
        res02 = fma52hi(res03, T, M[2]);
        res04 = fma52lo(res04, T, M[4]);
        res03 = fma52hi(res04, T, M[3]);
        res05 = fma52lo(res05, T, M[5]);
        res04 = fma52hi(res05, T, M[4]);
        res06 = fma52lo(res06, T, M[6]);
        res05 = fma52hi(res06, T, M[5]);
        res07 = fma52lo(res07, T, M[7]);
        res06 = fma52hi(res07, T, M[6]);
        res08 = fma52lo(res08, T, M[8]);
        res07 = fma52hi(res08, T, M[7]);
        res09 = fma52lo(res09, T, M[9]);
        res08 = fma52hi(res09, T, M[8]);
        res10 = fma52lo(res10, T, M[10]);
        res09 = fma52hi(res10, T, M[9]);
        res11 = fma52lo(res11, T, M[11]);
        res10 = fma52hi(res11, T, M[10]);
        res12 = fma52lo(res12, T, M[12]);
        res11 = fma52hi(res12, T, M[11]);
        res13 = fma52lo(res13, T, M[13]);
        res12 = fma52hi(res13, T, M[12]);
        res14 = fma52lo(res14, T, M[14]);
        res13 = fma52hi(res14, T, M[13]);
        res15 = fma52lo(res15, T, M[15]);
        res14 = fma52hi(res15, T, M[14]);
        res16 = fma52lo(res16, T, M[16]);
        res15 = fma52hi(res16, T, M[15]);
        res17 = fma52lo(res17, T, M[17]);
        res16 = fma52hi(res17, T, M[16]);
        res18 = fma52lo(res18, T, M[18]);
        res17 = fma52hi(res18, T, M[17]);
        res19 = fma52lo(res19, T, M[19]);
        res18 = fma52hi(res19, T, M[18]);
        res19 = fma52hi(get_zero64(), T, M[19]);
    }
    // Normalization
    U64 High_Extra_Bits = srli64(res00, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 0, res00);

    res01           = add64(res01, High_Extra_Bits);
    High_Extra_Bits = srli64(res01, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 1, res01);

    res02           = add64(res02, High_Extra_Bits);
    High_Extra_Bits = srli64(res02, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 2, res02);

    res03           = add64(res03, High_Extra_Bits);
    High_Extra_Bits = srli64(res03, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 3, res03);

    res04           = add64(res04, High_Extra_Bits);
    High_Extra_Bits = srli64(res04, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 4, res04);

    res05           = add64(res05, High_Extra_Bits);
    High_Extra_Bits = srli64(res05, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 5, res05);

    res06           = add64(res06, High_Extra_Bits);
    High_Extra_Bits = srli64(res06, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 6, res06);

    res07           = add64(res07, High_Extra_Bits);
    High_Extra_Bits = srli64(res07, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 7, res07);

    res08           = add64(res08, High_Extra_Bits);
    High_Extra_Bits = srli64(res08, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 8, res08);

    res09           = add64(res09, High_Extra_Bits);
    High_Extra_Bits = srli64(res09, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 9, res09);

    res10           = add64(res10, High_Extra_Bits);
    High_Extra_Bits = srli64(res10, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 10, res10);

    res11           = add64(res11, High_Extra_Bits);
    High_Extra_Bits = srli64(res11, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 11, res11);

    res12           = add64(res12, High_Extra_Bits);
    High_Extra_Bits = srli64(res12, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 12, res12);

    res13           = add64(res13, High_Extra_Bits);
    High_Extra_Bits = srli64(res13, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 13, res13);

    res14           = add64(res14, High_Extra_Bits);
    High_Extra_Bits = srli64(res14, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 14, res14);

    res15           = add64(res15, High_Extra_Bits);
    High_Extra_Bits = srli64(res15, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 15, res15);

    res16           = add64(res16, High_Extra_Bits);
    High_Extra_Bits = srli64(res16, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 16, res16);

    res17           = add64(res17, High_Extra_Bits);
    High_Extra_Bits = srli64(res17, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 17, res17);

    res18           = add64(res18, High_Extra_Bits);
    High_Extra_Bits = srli64(res18, DIGIT_SIZE);
    storeu64(out_mb + MB_WIDTH * 18, res18);

    res19 = add64(res19, High_Extra_Bits);
    storeu64(out_mb + MB_WIDTH * 19, res19);
}

#endif /* #if (_MBX>=_MBX_K1) */
