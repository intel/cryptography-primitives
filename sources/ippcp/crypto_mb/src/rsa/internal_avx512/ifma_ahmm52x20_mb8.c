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

/*
Almost Half Montgomery Multiplication (AHMM)

Output:
    out_mb   : c = A*B*(2^(-20*52)) mod M
Inputs:
    inpA_mb  : A
    inpB_mb  : B
    inpBx_mb : K = B*(2^(-10*52)) mod M
    inpM_mb  : M
    k0_mb    : mont_constant = (-M^(-1) mod 2^(52))

    AL=A[ 9: 0]
    AH=A[19:10]

    C=0
    for i from 0 to 9:
        C=C+AL[i]*K+AH[i]*B
        T=C[0]*mu	// discard T[1]
        C=C+T[0]*M	// C[0] is zero
        C=C>>52		// at each step of the for loop, divide the result by 2^52
    return C
*/

#if (_MBX >= _MBX_K1)

void ifma_ahmm52x20_mb8(int64u* out_mb,
                        const int64u* inpA_mb,
                        const int64u* inpB_mb,
                        const int64u* inpBx_mb,
                        const int64u* inpM_mb,
                        const int64u* k0_mb)
{

    // Temporary Registers to hold 20 52-bit intermediate results
    U64 res00, res01, res02, res03, res04, res05, res06, res07, res08, res09, res10, res11, res12,
        res13, res14, res15, res16, res17, res18, res19, res20;

    // Precomputed Montgomery constant (-M^(-1) mod 2^(52))
    const U64 mont_constant = loadu64(k0_mb);

    // C = 0
    res00 = res01 = res02 = res03 = res04 = res05 = res06 = res07 = res08 = res09 = res10 = res11 =
        res12 = res13 = res14 = res15 = res16 = res17 = res18 = res19 = res20 = get_zero64();

    U64* A     = (U64*)inpA_mb;
    U64* M     = (U64*)inpM_mb;
    U64* mulb  = (U64*)inpB_mb;
    U64* mulbx = (U64*)inpBx_mb;

    for (int itr = 0; itr < 10; itr++) {
        //******************************************************
        // C=C+AL[i]*K+AH[i]*B
        //******************************************************

        // C=C+AH[i]*B
        // load AH[i]
        const U64 AHi = A[itr + 10]; // AH=A[19:10]
        res00         = fma52lo(res00, AHi, mulb[0]);
        res01         = fma52hi(res01, AHi, mulb[0]);
        res01         = fma52lo(res01, AHi, mulb[1]);
        res02         = fma52hi(res02, AHi, mulb[1]);
        res02         = fma52lo(res02, AHi, mulb[2]);
        res03         = fma52hi(res03, AHi, mulb[2]);
        res03         = fma52lo(res03, AHi, mulb[3]);
        res04         = fma52hi(res04, AHi, mulb[3]);
        res04         = fma52lo(res04, AHi, mulb[4]);
        res05         = fma52hi(res05, AHi, mulb[4]);
        res05         = fma52lo(res05, AHi, mulb[5]);
        res06         = fma52hi(res06, AHi, mulb[5]);
        res06         = fma52lo(res06, AHi, mulb[6]);
        res07         = fma52hi(res07, AHi, mulb[6]);
        res07         = fma52lo(res07, AHi, mulb[7]);
        res08         = fma52hi(res08, AHi, mulb[7]);
        res08         = fma52lo(res08, AHi, mulb[8]);
        res09         = fma52hi(res09, AHi, mulb[8]);
        res09         = fma52lo(res09, AHi, mulb[9]);
        res10         = fma52hi(res10, AHi, mulb[9]);
        res10         = fma52lo(res10, AHi, mulb[10]);
        res11         = fma52hi(res11, AHi, mulb[10]);
        res11         = fma52lo(res11, AHi, mulb[11]);
        res12         = fma52hi(res12, AHi, mulb[11]);
        res12         = fma52lo(res12, AHi, mulb[12]);
        res13         = fma52hi(res13, AHi, mulb[12]);
        res13         = fma52lo(res13, AHi, mulb[13]);
        res14         = fma52hi(res14, AHi, mulb[13]);
        res14         = fma52lo(res14, AHi, mulb[14]);
        res15         = fma52hi(res15, AHi, mulb[14]);
        res15         = fma52lo(res15, AHi, mulb[15]);
        res16         = fma52hi(res16, AHi, mulb[15]);
        res16         = fma52lo(res16, AHi, mulb[16]);
        res17         = fma52hi(res17, AHi, mulb[16]);
        res17         = fma52lo(res17, AHi, mulb[17]);
        res18         = fma52hi(res18, AHi, mulb[17]);
        res18         = fma52lo(res18, AHi, mulb[18]);
        res19         = fma52hi(res19, AHi, mulb[18]);
        res19         = fma52lo(res19, AHi, mulb[19]);
        res20         = fma52hi(get_zero64(), AHi, mulb[19]);

        // C=C+AL[i]*K (low part)
        // load AL[i]
        const U64 ALi = A[itr]; // AL=A[ 9: 0]
        res00         = fma52lo(res00, ALi, mulbx[0]);
        res01         = fma52hi(res01, ALi, mulbx[0]);
        res01         = fma52lo(res01, ALi, mulbx[1]);
        res02         = fma52hi(res02, ALi, mulbx[1]);
        res02         = fma52lo(res02, ALi, mulbx[2]);
        res03         = fma52hi(res03, ALi, mulbx[2]);
        res03         = fma52lo(res03, ALi, mulbx[3]);
        res04         = fma52hi(res04, ALi, mulbx[3]);
        res04         = fma52lo(res04, ALi, mulbx[4]);
        res05         = fma52hi(res05, ALi, mulbx[4]);
        res05         = fma52lo(res05, ALi, mulbx[5]);
        res06         = fma52hi(res06, ALi, mulbx[5]);
        res06         = fma52lo(res06, ALi, mulbx[6]);
        res07         = fma52hi(res07, ALi, mulbx[6]);
        res07         = fma52lo(res07, ALi, mulbx[7]);
        res08         = fma52hi(res08, ALi, mulbx[7]);
        res08         = fma52lo(res08, ALi, mulbx[8]);
        res09         = fma52hi(res09, ALi, mulbx[8]);
        res09         = fma52lo(res09, ALi, mulbx[9]);
        res10         = fma52hi(res10, ALi, mulbx[9]);
        res10         = fma52lo(res10, ALi, mulbx[10]);
        res11         = fma52hi(res11, ALi, mulbx[10]);
        res11         = fma52lo(res11, ALi, mulbx[11]);
        res12         = fma52hi(res12, ALi, mulbx[11]);
        res12         = fma52lo(res12, ALi, mulbx[12]);
        res13         = fma52hi(res13, ALi, mulbx[12]);
        res13         = fma52lo(res13, ALi, mulbx[13]);
        res14         = fma52hi(res14, ALi, mulbx[13]);
        res14         = fma52lo(res14, ALi, mulbx[14]);
        res15         = fma52hi(res15, ALi, mulbx[14]);
        res15         = fma52lo(res15, ALi, mulbx[15]);
        res16         = fma52hi(res16, ALi, mulbx[15]);
        res16         = fma52lo(res16, ALi, mulbx[16]);
        res17         = fma52hi(res17, ALi, mulbx[16]);
        res17         = fma52lo(res17, ALi, mulbx[17]);
        res18         = fma52hi(res18, ALi, mulbx[17]);
        res18         = fma52lo(res18, ALi, mulbx[18]);
        res19         = fma52hi(res19, ALi, mulbx[18]);
        res19         = fma52lo(res19, ALi, mulbx[19]);
        res20         = fma52hi(res20, ALi, mulbx[19]);
        // done: C=C+AL[i]*K+AH[i]*B
        //******************************************************

        // T=C[0]*mu
        U64 T = fma52lo(get_zero64(), res00, mont_constant);

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
        res19 = fma52hi(res20, T, M[19]);
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
