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
#include <internal/rsa/ifma_rsa_arith.h>

/*
Two independent functions are stitched:
- 4 squarings
- Extracting values from the precomputed tables MulTbl and MulTblx


For squaring, an optimized approach is utilized. As an example, suppose we are multiplying two 4-digit numbers:
                                    | a3 | a2 | a1 | a0 |
                                    | b3 | b2 | b1 | b0 |
                                  X______________________

                | a3 * b3 | a2 * b2 | a1 * b1 | a0 * b0 |
                     | a3 * b2 | a2 * b1 | a1 * b0 |
                     | a2 * b3 | a1 * b2 | a0 * b1 |
                          | a3 * b1 | a2 * b0 |
                          | a1 * b3 | a0 * b2 |
                               | a3 * b0 |
                               | a0 * b3 |

This operation is realized with 4x4=16 digit-wise multiplications. When a=b (for squaring), multiplication operation is optimizes as follows:
                                    | a3 | a2 | a1 | a0 |
                                    | a3 | a2 | a1 | a0 |
                                  X______________________

                | a3 * a3 | a2 * a2 | a1 * a1 | a0 * a0 |
            2*       | a3 * a2 | a2 * a1 | a1 * a0 |

            2*            | a3 * a1 | a2 * a0 |

            2*                 | a3 * a0 |

This operation is realized with 10 digit-wise multiplications. For an n-digit squaring operation, (n^2-n)/2 less digit-wise multiplications are
required. The number of digit-wise multiplications for n-digit squaring can be calculated with the following equation:

    n^2 - (n^2-n)/2

multiplication by 2 operations are realized with add64 instructions.
*/

#if (_MBX >= _MBX_K1)

void AMS4x52x20_diagonal_stitched_with_extract_mb8(int64u* out_mb,
                                                   U64* mulb,
                                                   U64* mulbx,
                                                   const int64u* inpA_mb,
                                                   const int64u* inpM_mb,
                                                   const int64u* k0_mb,
                                                   int64u MulTbl[][redLen2K][8],
                                                   int64u MulTblx[][redLen2K][8],
                                                   const int64u Idx[8])
{

    U64 res00, res01, res02, res03, res04, res05, res06, res07, res08, res09, res10, res11, res12,
        res13, res14, res15, res16, res17, res18, res19, res20, res21, res22, res23, res24, res25,
        res26, res27, res28, res29, res30, res31, res32, res33, res34, res35, res36, res37, res38,
        res39;

    const U64 mont_constant = loadu64((U64*)k0_mb);

    U64* a = (U64*)inpA_mb;
    U64* m = (U64*)inpM_mb;
    U64* r = (U64*)out_mb;

    U64 idx_target            = loadu64((U64*)Idx);
    __mmask8 extract_sel_mask = cmpeq64_mask(set64(0), idx_target);

    for (int iter = 0; iter < 4; ++iter) {
        res00 = res01 = res02 = res03 = res04 = res05 = res06 = res07 = res08 = res09 = res10 =
            res11 = res12 = res13 = res14 = res15 = res16 = res17 = res18 = res19 = res20 = res21 =
                res22 = res23 = res24 = res25 = res26 = res27 = res28 = res29 = res30 = res31 =
                    res32 = res33 = res34 = res35 = res36 = res37 = res38 = res39 = get_zero64();

        // Calculate full square
        // stitched with extraction code

        //*******BEGIN SQUARING CODE SEGMENT************//
        res01 = fma52lo(res01, a[0], a[1]); // Sum(1)
        res02 = fma52hi(res02, a[0], a[1]); // Sum(1)
        res02 = fma52lo(res02, a[0], a[2]); // Sum(2)
        res03 = fma52hi(res03, a[0], a[2]); // Sum(2)
        res03 = fma52lo(res03, a[1], a[2]); // Sum(3)
        res04 = fma52hi(res04, a[1], a[2]); // Sum(3)
        res03 = fma52lo(res03, a[0], a[3]); // Sum(3)
        res04 = fma52hi(res04, a[0], a[3]); // Sum(3)
        res04 = fma52lo(res04, a[1], a[3]); // Sum(4)
        res05 = fma52hi(res05, a[1], a[3]); // Sum(4)
        res05 = fma52lo(res05, a[2], a[3]); // Sum(5)
        res06 = fma52hi(res06, a[2], a[3]); // Sum(5)
        res04 = fma52lo(res04, a[0], a[4]); // Sum(4)
        res05 = fma52hi(res05, a[0], a[4]); // Sum(4)
        res05 = fma52lo(res05, a[1], a[4]); // Sum(5)
        res06 = fma52hi(res06, a[1], a[4]); // Sum(5)
        res06 = fma52lo(res06, a[2], a[4]); // Sum(6)
        res07 = fma52hi(res07, a[2], a[4]); // Sum(6)
        res07 = fma52lo(res07, a[3], a[4]); // Sum(7)
        res08 = fma52hi(res08, a[3], a[4]); // Sum(7)
        res05 = fma52lo(res05, a[0], a[5]); // Sum(5)
        res06 = fma52hi(res06, a[0], a[5]); // Sum(5)
        res06 = fma52lo(res06, a[1], a[5]); // Sum(6)
        res07 = fma52hi(res07, a[1], a[5]); // Sum(6)
        res07 = fma52lo(res07, a[2], a[5]); // Sum(7)
        res08 = fma52hi(res08, a[2], a[5]); // Sum(7)
        res08 = fma52lo(res08, a[3], a[5]); // Sum(8)
        res09 = fma52hi(res09, a[3], a[5]); // Sum(8)
        res09 = fma52lo(res09, a[4], a[5]); // Sum(9)
        res10 = fma52hi(res10, a[4], a[5]); // Sum(9)
        res06 = fma52lo(res06, a[0], a[6]); // Sum(6)
        res07 = fma52hi(res07, a[0], a[6]); // Sum(6)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        U64 idx_curr                   = set64(1 + 4 * iter);
        __mmask8 extract_sel_mask_next = cmpeq64_mask(idx_curr, idx_target);
        U64 temp                       = loadstream64(MulTbl[0 + 4 * iter][0]);
        mulb[0]                        = _mm512_mask_mov_epi64(mulb[0], extract_sel_mask, temp);
        temp                           = loadstream64(MulTbl[0 + 4 * iter][1]);
        mulb[1]                        = _mm512_mask_mov_epi64(mulb[1], extract_sel_mask, temp);
        temp                           = loadstream64(MulTbl[0 + 4 * iter][2]);
        mulb[2]                        = _mm512_mask_mov_epi64(mulb[2], extract_sel_mask, temp);
        temp                           = loadstream64(MulTbl[0 + 4 * iter][3]);
        mulb[3]                        = _mm512_mask_mov_epi64(mulb[3], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res07 = fma52lo(res07, a[1], a[6]); // Sum(7)
        res08 = fma52hi(res08, a[1], a[6]); // Sum(7)
        res08 = fma52lo(res08, a[2], a[6]); // Sum(8)
        res09 = fma52hi(res09, a[2], a[6]); // Sum(8)
        res09 = fma52lo(res09, a[3], a[6]); // Sum(9)
        res10 = fma52hi(res10, a[3], a[6]); // Sum(9)
        res10 = fma52lo(res10, a[4], a[6]); // Sum(10)
        res11 = fma52hi(res11, a[4], a[6]); // Sum(10)
        res11 = fma52lo(res11, a[5], a[6]); // Sum(11)
        res12 = fma52hi(res12, a[5], a[6]); // Sum(11)
        res07 = fma52lo(res07, a[0], a[7]); // Sum(7)
        res08 = fma52hi(res08, a[0], a[7]); // Sum(7)
        res08 = fma52lo(res08, a[1], a[7]); // Sum(8)
        res09 = fma52hi(res09, a[1], a[7]); // Sum(8)
        res09 = fma52lo(res09, a[2], a[7]); // Sum(9)
        res10 = fma52hi(res10, a[2], a[7]); // Sum(9)
        res10 = fma52lo(res10, a[3], a[7]); // Sum(10)
        res11 = fma52hi(res11, a[3], a[7]); // Sum(10)
        res11 = fma52lo(res11, a[4], a[7]); // Sum(11)
        res12 = fma52hi(res12, a[4], a[7]); // Sum(11)
        res08 = fma52lo(res08, a[0], a[8]); // Sum(8)
        res09 = fma52hi(res09, a[0], a[8]); // Sum(8)
        res09 = fma52lo(res09, a[1], a[8]); // Sum(9)
        res10 = fma52hi(res10, a[1], a[8]); // Sum(9)
        res10 = fma52lo(res10, a[2], a[8]); // Sum(10)
        res11 = fma52hi(res11, a[2], a[8]); // Sum(10)
        res11 = fma52lo(res11, a[3], a[8]); // Sum(11)
        res12 = fma52hi(res12, a[3], a[8]); // Sum(11)
        res09 = fma52lo(res09, a[0], a[9]); // Sum(9)
        res10 = fma52hi(res10, a[0], a[9]); // Sum(9)
        res10 = fma52lo(res10, a[1], a[9]); // Sum(10)
        res11 = fma52hi(res11, a[1], a[9]); // Sum(10
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp    = loadstream64(MulTbl[0 + 4 * iter][4]);
        mulb[4] = _mm512_mask_mov_epi64(mulb[4], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[0 + 4 * iter][5]);
        mulb[5] = _mm512_mask_mov_epi64(mulb[5], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[0 + 4 * iter][6]);
        mulb[6] = _mm512_mask_mov_epi64(mulb[6], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[0 + 4 * iter][7]);
        mulb[7] = _mm512_mask_mov_epi64(mulb[7], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res11 = fma52lo(res11, a[2], a[9]);  // Sum(11)
        res12 = fma52hi(res12, a[2], a[9]);  // Sum(11)
        res10 = fma52lo(res10, a[0], a[10]); // Sum(10)
        res11 = fma52hi(res11, a[0], a[10]); // Sum(10)
        res11 = fma52lo(res11, a[1], a[10]); // Sum(11)
        res12 = fma52hi(res12, a[1], a[10]); // Sum(11)
        res11 = fma52lo(res11, a[0], a[11]); // Sum(11)
        res12 = fma52hi(res12, a[0], a[11]); // Sum(11)
        res01 = add64(res01, res01);         // Double(1)
        res02 = add64(res02, res02);         // Double(2)
        res03 = add64(res03, res03);         // Double(3)
        res04 = add64(res04, res04);         // Double(4)
        res05 = add64(res05, res05);         // Double(5)
        res06 = add64(res06, res06);         // Double(6)
        res07 = add64(res07, res07);         // Double(7)
        res08 = add64(res08, res08);         // Double(8)
        res09 = add64(res09, res09);         // Double(9)
        res10 = add64(res10, res10);         // Double(10)
        res11 = add64(res11, res11);         // Double(11)
        res00 = fma52lo(res00, a[0], a[0]);  // Add sqr(0)
        res01 = fma52hi(res01, a[0], a[0]);  // Add sqr(0)
        res02 = fma52lo(res02, a[1], a[1]);  // Add sqr(2)
        res03 = fma52hi(res03, a[1], a[1]);  // Add sqr(2)
        res04 = fma52lo(res04, a[2], a[2]);  // Add sqr(4)
        res05 = fma52hi(res05, a[2], a[2]);  // Add sqr(4)
        res06 = fma52lo(res06, a[3], a[3]);  // Add sqr(6)
        res07 = fma52hi(res07, a[3], a[3]);  // Add sqr(6)
        res08 = fma52lo(res08, a[4], a[4]);  // Add sqr(8)
        res09 = fma52hi(res09, a[4], a[4]);  // Add sqr(8)
        res10 = fma52lo(res10, a[5], a[5]);  // Add sqr(10)
        res11 = fma52hi(res11, a[5], a[5]);  // Add sqr(10)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[0 + 4 * iter][8]);
        mulb[8]  = _mm512_mask_mov_epi64(mulb[8], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[0 + 4 * iter][9]);
        mulb[9]  = _mm512_mask_mov_epi64(mulb[9], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[0 + 4 * iter][10]);
        mulb[10] = _mm512_mask_mov_epi64(mulb[10], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[0 + 4 * iter][11]);
        mulb[11] = _mm512_mask_mov_epi64(mulb[11], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res12 = fma52lo(res12, a[5], a[7]);  // Sum(12)
        res13 = fma52hi(res13, a[5], a[7]);  // Sum(12)
        res13 = fma52lo(res13, a[6], a[7]);  // Sum(13)
        res14 = fma52hi(res14, a[6], a[7]);  // Sum(13)
        res12 = fma52lo(res12, a[4], a[8]);  // Sum(12)
        res13 = fma52hi(res13, a[4], a[8]);  // Sum(12)
        res13 = fma52lo(res13, a[5], a[8]);  // Sum(13)
        res14 = fma52hi(res14, a[5], a[8]);  // Sum(13)
        res14 = fma52lo(res14, a[6], a[8]);  // Sum(14)
        res15 = fma52hi(res15, a[6], a[8]);  // Sum(14)
        res15 = fma52lo(res15, a[7], a[8]);  // Sum(15)
        res16 = fma52hi(res16, a[7], a[8]);  // Sum(15)
        res12 = fma52lo(res12, a[3], a[9]);  // Sum(12)
        res13 = fma52hi(res13, a[3], a[9]);  // Sum(12)
        res13 = fma52lo(res13, a[4], a[9]);  // Sum(13)
        res14 = fma52hi(res14, a[4], a[9]);  // Sum(13)
        res14 = fma52lo(res14, a[5], a[9]);  // Sum(14)
        res15 = fma52hi(res15, a[5], a[9]);  // Sum(14)
        res15 = fma52lo(res15, a[6], a[9]);  // Sum(15)
        res16 = fma52hi(res16, a[6], a[9]);  // Sum(15)
        res16 = fma52lo(res16, a[7], a[9]);  // Sum(16)
        res17 = fma52hi(res17, a[7], a[9]);  // Sum(16)
        res17 = fma52lo(res17, a[8], a[9]);  // Sum(17)
        res18 = fma52hi(res18, a[8], a[9]);  // Sum(17)
        res12 = fma52lo(res12, a[2], a[10]); // Sum(12)
        res13 = fma52hi(res13, a[2], a[10]); // Sum(12)
        res13 = fma52lo(res13, a[3], a[10]); // Sum(13)
        res14 = fma52hi(res14, a[3], a[10]); // Sum(13)
        res14 = fma52lo(res14, a[4], a[10]); // Sum(14)
        res15 = fma52hi(res15, a[4], a[10]); // Sum(14)
        res15 = fma52lo(res15, a[5], a[10]); // Sum(15)
        res16 = fma52hi(res16, a[5], a[10]); // Sum(15)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[0 + 4 * iter][12]);
        mulb[12] = _mm512_mask_mov_epi64(mulb[12], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[0 + 4 * iter][13]);
        mulb[13] = _mm512_mask_mov_epi64(mulb[13], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[0 + 4 * iter][14]);
        mulb[14] = _mm512_mask_mov_epi64(mulb[14], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[0 + 4 * iter][15]);
        mulb[15] = _mm512_mask_mov_epi64(mulb[15], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res16 = fma52lo(res16, a[6], a[10]);  // Sum(16)
        res17 = fma52hi(res17, a[6], a[10]);  // Sum(16)
        res17 = fma52lo(res17, a[7], a[10]);  // Sum(17)
        res18 = fma52hi(res18, a[7], a[10]);  // Sum(17)
        res18 = fma52lo(res18, a[8], a[10]);  // Sum(18)
        res19 = fma52hi(res19, a[8], a[10]);  // Sum(18)
        res19 = fma52lo(res19, a[9], a[10]);  // Sum(19)
        res20 = fma52hi(res20, a[9], a[10]);  // Sum(19)
        res12 = fma52lo(res12, a[1], a[11]);  // Sum(12)
        res13 = fma52hi(res13, a[1], a[11]);  // Sum(12)
        res13 = fma52lo(res13, a[2], a[11]);  // Sum(13)
        res14 = fma52hi(res14, a[2], a[11]);  // Sum(13)
        res14 = fma52lo(res14, a[3], a[11]);  // Sum(14)
        res15 = fma52hi(res15, a[3], a[11]);  // Sum(14)
        res15 = fma52lo(res15, a[4], a[11]);  // Sum(15)
        res16 = fma52hi(res16, a[4], a[11]);  // Sum(15)
        res16 = fma52lo(res16, a[5], a[11]);  // Sum(16)
        res17 = fma52hi(res17, a[5], a[11]);  // Sum(16)
        res17 = fma52lo(res17, a[6], a[11]);  // Sum(17)
        res18 = fma52hi(res18, a[6], a[11]);  // Sum(17)
        res18 = fma52lo(res18, a[7], a[11]);  // Sum(18)
        res19 = fma52hi(res19, a[7], a[11]);  // Sum(18)
        res19 = fma52lo(res19, a[8], a[11]);  // Sum(19)
        res20 = fma52hi(res20, a[8], a[11]);  // Sum(19)
        res20 = fma52lo(res20, a[9], a[11]);  // Sum(20)
        res21 = fma52hi(res21, a[9], a[11]);  // Sum(20)
        res21 = fma52lo(res21, a[10], a[11]); // Sum(21)
        res22 = fma52hi(res22, a[10], a[11]); // Sum(21)
        res12 = fma52lo(res12, a[0], a[12]);  // Sum(12)
        res13 = fma52hi(res13, a[0], a[12]);  // Sum(12)
        res13 = fma52lo(res13, a[1], a[12]);  // Sum(13)
        res14 = fma52hi(res14, a[1], a[12]);  // Sum(13)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[0 + 4 * iter][16]);
        mulb[16] = _mm512_mask_mov_epi64(mulb[16], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[0 + 4 * iter][17]);
        mulb[17] = _mm512_mask_mov_epi64(mulb[17], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[0 + 4 * iter][18]);
        mulb[18] = _mm512_mask_mov_epi64(mulb[18], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[0 + 4 * iter][19]);
        mulb[19] = _mm512_mask_mov_epi64(mulb[19], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res14 = fma52lo(res14, a[2], a[12]);  // Sum(14)
        res15 = fma52hi(res15, a[2], a[12]);  // Sum(14)
        res15 = fma52lo(res15, a[3], a[12]);  // Sum(15)
        res16 = fma52hi(res16, a[3], a[12]);  // Sum(15)
        res16 = fma52lo(res16, a[4], a[12]);  // Sum(16)
        res17 = fma52hi(res17, a[4], a[12]);  // Sum(16)
        res17 = fma52lo(res17, a[5], a[12]);  // Sum(17)
        res18 = fma52hi(res18, a[5], a[12]);  // Sum(17)
        res18 = fma52lo(res18, a[6], a[12]);  // Sum(18)
        res19 = fma52hi(res19, a[6], a[12]);  // Sum(18)
        res19 = fma52lo(res19, a[7], a[12]);  // Sum(19)
        res20 = fma52hi(res20, a[7], a[12]);  // Sum(19)
        res20 = fma52lo(res20, a[8], a[12]);  // Sum(20)
        res21 = fma52hi(res21, a[8], a[12]);  // Sum(20)
        res21 = fma52lo(res21, a[9], a[12]);  // Sum(21)
        res22 = fma52hi(res22, a[9], a[12]);  // Sum(21)
        res22 = fma52lo(res22, a[10], a[12]); // Sum(22)
        res23 = fma52hi(res23, a[10], a[12]); // Sum(22)
        res23 = fma52lo(res23, a[11], a[12]); // Sum(23)
        res24 = fma52hi(res24, a[11], a[12]); // Sum(23)
        res13 = fma52lo(res13, a[0], a[13]);  // Sum(13)
        res14 = fma52hi(res14, a[0], a[13]);  // Sum(13)
        res14 = fma52lo(res14, a[1], a[13]);  // Sum(14)
        res15 = fma52hi(res15, a[1], a[13]);  // Sum(14)
        res15 = fma52lo(res15, a[2], a[13]);  // Sum(15)
        res16 = fma52hi(res16, a[2], a[13]);  // Sum(15)
        res16 = fma52lo(res16, a[3], a[13]);  // Sum(16)
        res17 = fma52hi(res17, a[3], a[13]);  // Sum(16)
        res17 = fma52lo(res17, a[4], a[13]);  // Sum(17)
        res18 = fma52hi(res18, a[4], a[13]);  // Sum(17)
        res18 = fma52lo(res18, a[5], a[13]);  // Sum(18)
        res19 = fma52hi(res19, a[5], a[13]);  // Sum(18)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        U64 tempx = loadstream64(MulTblx[0 + 4 * iter][0]);
        mulbx[0]  = _mm512_mask_mov_epi64(mulbx[0], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[0 + 4 * iter][1]);
        mulbx[1]  = _mm512_mask_mov_epi64(mulbx[1], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[0 + 4 * iter][2]);
        mulbx[2]  = _mm512_mask_mov_epi64(mulbx[2], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[0 + 4 * iter][3]);
        mulbx[3]  = _mm512_mask_mov_epi64(mulbx[3], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res19 = fma52lo(res19, a[6], a[13]);  // Sum(19)
        res20 = fma52hi(res20, a[6], a[13]);  // Sum(19)
        res20 = fma52lo(res20, a[7], a[13]);  // Sum(20)
        res21 = fma52hi(res21, a[7], a[13]);  // Sum(20)
        res21 = fma52lo(res21, a[8], a[13]);  // Sum(21)
        res22 = fma52hi(res22, a[8], a[13]);  // Sum(21)
        res22 = fma52lo(res22, a[9], a[13]);  // Sum(22)
        res23 = fma52hi(res23, a[9], a[13]);  // Sum(22)
        res23 = fma52lo(res23, a[10], a[13]); // Sum(23)
        res24 = fma52hi(res24, a[10], a[13]); // Sum(23)
        res14 = fma52lo(res14, a[0], a[14]);  // Sum(14)
        res15 = fma52hi(res15, a[0], a[14]);  // Sum(14)
        res15 = fma52lo(res15, a[1], a[14]);  // Sum(15)
        res16 = fma52hi(res16, a[1], a[14]);  // Sum(15)
        res16 = fma52lo(res16, a[2], a[14]);  // Sum(16)
        res17 = fma52hi(res17, a[2], a[14]);  // Sum(16)
        res17 = fma52lo(res17, a[3], a[14]);  // Sum(17)
        res18 = fma52hi(res18, a[3], a[14]);  // Sum(17)
        res18 = fma52lo(res18, a[4], a[14]);  // Sum(18)
        res19 = fma52hi(res19, a[4], a[14]);  // Sum(18)
        res19 = fma52lo(res19, a[5], a[14]);  // Sum(19)
        res20 = fma52hi(res20, a[5], a[14]);  // Sum(19)
        res20 = fma52lo(res20, a[6], a[14]);  // Sum(20)
        res21 = fma52hi(res21, a[6], a[14]);  // Sum(20)
        res21 = fma52lo(res21, a[7], a[14]);  // Sum(21)
        res22 = fma52hi(res22, a[7], a[14]);  // Sum(21)
        res22 = fma52lo(res22, a[8], a[14]);  // Sum(22)
        res23 = fma52hi(res23, a[8], a[14]);  // Sum(22)
        res23 = fma52lo(res23, a[9], a[14]);  // Sum(23)
        res24 = fma52hi(res24, a[9], a[14]);  // Sum(23)
        res15 = fma52lo(res15, a[0], a[15]);  // Sum(15)
        res16 = fma52hi(res16, a[0], a[15]);  // Sum(15)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx    = loadstream64(MulTblx[0 + 4 * iter][4]);
        mulbx[4] = _mm512_mask_mov_epi64(mulbx[4], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[0 + 4 * iter][5]);
        mulbx[5] = _mm512_mask_mov_epi64(mulbx[5], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[0 + 4 * iter][6]);
        mulbx[6] = _mm512_mask_mov_epi64(mulbx[6], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[0 + 4 * iter][7]);
        mulbx[7] = _mm512_mask_mov_epi64(mulbx[7], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res16 = fma52lo(res16, a[1], a[15]); // Sum(16)
        res17 = fma52hi(res17, a[1], a[15]); // Sum(16)
        res17 = fma52lo(res17, a[2], a[15]); // Sum(17)
        res18 = fma52hi(res18, a[2], a[15]); // Sum(17)
        res18 = fma52lo(res18, a[3], a[15]); // Sum(18)
        res19 = fma52hi(res19, a[3], a[15]); // Sum(18)
        res19 = fma52lo(res19, a[4], a[15]); // Sum(19)
        res20 = fma52hi(res20, a[4], a[15]); // Sum(19)
        res20 = fma52lo(res20, a[5], a[15]); // Sum(20)
        res21 = fma52hi(res21, a[5], a[15]); // Sum(20)
        res21 = fma52lo(res21, a[6], a[15]); // Sum(21)
        res22 = fma52hi(res22, a[6], a[15]); // Sum(21)
        res22 = fma52lo(res22, a[7], a[15]); // Sum(22)
        res23 = fma52hi(res23, a[7], a[15]); // Sum(22)
        res23 = fma52lo(res23, a[8], a[15]); // Sum(23)
        res24 = fma52hi(res24, a[8], a[15]); // Sum(23)
        res16 = fma52lo(res16, a[0], a[16]); // Sum(16)
        res17 = fma52hi(res17, a[0], a[16]); // Sum(16)
        res17 = fma52lo(res17, a[1], a[16]); // Sum(17)
        res18 = fma52hi(res18, a[1], a[16]); // Sum(17)
        res18 = fma52lo(res18, a[2], a[16]); // Sum(18)
        res19 = fma52hi(res19, a[2], a[16]); // Sum(18)
        res19 = fma52lo(res19, a[3], a[16]); // Sum(19)
        res20 = fma52hi(res20, a[3], a[16]); // Sum(19)
        res20 = fma52lo(res20, a[4], a[16]); // Sum(20)
        res21 = fma52hi(res21, a[4], a[16]); // Sum(20)
        res21 = fma52lo(res21, a[5], a[16]); // Sum(21)
        res22 = fma52hi(res22, a[5], a[16]); // Sum(21)
        res22 = fma52lo(res22, a[6], a[16]); // Sum(22)
        res23 = fma52hi(res23, a[6], a[16]); // Sum(22)
        res23 = fma52lo(res23, a[7], a[16]); // Sum(23)
        res24 = fma52hi(res24, a[7], a[16]); // Sum(23)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx     = loadstream64(MulTblx[0 + 4 * iter][8]);
        mulbx[8]  = _mm512_mask_mov_epi64(mulbx[8], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[0 + 4 * iter][9]);
        mulbx[9]  = _mm512_mask_mov_epi64(mulbx[9], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[0 + 4 * iter][10]);
        mulbx[10] = _mm512_mask_mov_epi64(mulbx[10], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[0 + 4 * iter][11]);
        mulbx[11] = _mm512_mask_mov_epi64(mulbx[11], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res17 = fma52lo(res17, a[0], a[17]); // Sum(17)
        res18 = fma52hi(res18, a[0], a[17]); // Sum(17)
        res18 = fma52lo(res18, a[1], a[17]); // Sum(18)
        res19 = fma52hi(res19, a[1], a[17]); // Sum(18)
        res19 = fma52lo(res19, a[2], a[17]); // Sum(19)
        res20 = fma52hi(res20, a[2], a[17]); // Sum(19)
        res20 = fma52lo(res20, a[3], a[17]); // Sum(20)
        res21 = fma52hi(res21, a[3], a[17]); // Sum(20)
        res21 = fma52lo(res21, a[4], a[17]); // Sum(21)
        res22 = fma52hi(res22, a[4], a[17]); // Sum(21)
        res22 = fma52lo(res22, a[5], a[17]); // Sum(22)
        res23 = fma52hi(res23, a[5], a[17]); // Sum(22)
        res23 = fma52lo(res23, a[6], a[17]); // Sum(23)
        res24 = fma52hi(res24, a[6], a[17]); // Sum(23)
        res18 = fma52lo(res18, a[0], a[18]); // Sum(18)
        res19 = fma52hi(res19, a[0], a[18]); // Sum(18)
        res19 = fma52lo(res19, a[1], a[18]); // Sum(19)
        res20 = fma52hi(res20, a[1], a[18]); // Sum(19)
        res20 = fma52lo(res20, a[2], a[18]); // Sum(20)
        res21 = fma52hi(res21, a[2], a[18]); // Sum(20)
        res21 = fma52lo(res21, a[3], a[18]); // Sum(21)
        res22 = fma52hi(res22, a[3], a[18]); // Sum(21)
        res22 = fma52lo(res22, a[4], a[18]); // Sum(22)
        res23 = fma52hi(res23, a[4], a[18]); // Sum(22)
        res23 = fma52lo(res23, a[5], a[18]); // Sum(23)
        res24 = fma52hi(res24, a[5], a[18]); // Sum(23)
        res19 = fma52lo(res19, a[0], a[19]); // Sum(19)
        res20 = fma52hi(res20, a[0], a[19]); // Sum(19)
        res20 = fma52lo(res20, a[1], a[19]); // Sum(20)
        res21 = fma52hi(res21, a[1], a[19]); // Sum(20)
        res21 = fma52lo(res21, a[2], a[19]); // Sum(21)
        res22 = fma52hi(res22, a[2], a[19]); // Sum(21)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx     = loadstream64(MulTblx[0 + 4 * iter][12]);
        mulbx[12] = _mm512_mask_mov_epi64(mulbx[12], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[0 + 4 * iter][13]);
        mulbx[13] = _mm512_mask_mov_epi64(mulbx[13], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[0 + 4 * iter][14]);
        mulbx[14] = _mm512_mask_mov_epi64(mulbx[14], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[0 + 4 * iter][15]);
        mulbx[15] = _mm512_mask_mov_epi64(mulbx[15], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res22 = fma52lo(res22, a[3], a[19]);  // Sum(22)
        res23 = fma52hi(res23, a[3], a[19]);  // Sum(22)
        res23 = fma52lo(res23, a[4], a[19]);  // Sum(23)
        res24 = fma52hi(res24, a[4], a[19]);  // Sum(23)
        res12 = add64(res12, res12);          // Double(12)
        res13 = add64(res13, res13);          // Double(13)
        res14 = add64(res14, res14);          // Double(14)
        res15 = add64(res15, res15);          // Double(15)
        res16 = add64(res16, res16);          // Double(16)
        res17 = add64(res17, res17);          // Double(17)
        res18 = add64(res18, res18);          // Double(18)
        res19 = add64(res19, res19);          // Double(19)
        res20 = add64(res20, res20);          // Double(20)
        res21 = add64(res21, res21);          // Double(21)
        res22 = add64(res22, res22);          // Double(22)
        res23 = add64(res23, res23);          // Double(23)
        res12 = fma52lo(res12, a[6], a[6]);   // Add sqr(12)
        res13 = fma52hi(res13, a[6], a[6]);   // Add sqr(12)
        res14 = fma52lo(res14, a[7], a[7]);   // Add sqr(14)
        res15 = fma52hi(res15, a[7], a[7]);   // Add sqr(14)
        res16 = fma52lo(res16, a[8], a[8]);   // Add sqr(16)
        res17 = fma52hi(res17, a[8], a[8]);   // Add sqr(16)
        res18 = fma52lo(res18, a[9], a[9]);   // Add sqr(18)
        res19 = fma52hi(res19, a[9], a[9]);   // Add sqr(18)
        res20 = fma52lo(res20, a[10], a[10]); // Add sqr(20)
        res21 = fma52hi(res21, a[10], a[10]); // Add sqr(20)
        res22 = fma52lo(res22, a[11], a[11]); // Add sqr(22)
        res23 = fma52hi(res23, a[11], a[11]); // Add sqr(22)
        res24 = fma52lo(res24, a[11], a[13]); // Sum(24)
        res25 = fma52hi(res25, a[11], a[13]); // Sum(24)
        res25 = fma52lo(res25, a[12], a[13]); // Sum(25)
        res26 = fma52hi(res26, a[12], a[13]); // Sum(25)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx            = loadstream64(MulTblx[0 + 4 * iter][16]);
        mulbx[16]        = _mm512_mask_mov_epi64(mulbx[16], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[0 + 4 * iter][17]);
        mulbx[17]        = _mm512_mask_mov_epi64(mulbx[17], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[0 + 4 * iter][18]);
        mulbx[18]        = _mm512_mask_mov_epi64(mulbx[18], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[0 + 4 * iter][19]);
        mulbx[19]        = _mm512_mask_mov_epi64(mulbx[19], extract_sel_mask, tempx);
        extract_sel_mask = extract_sel_mask_next;
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res24 = fma52lo(res24, a[10], a[14]); // Sum(24)
        res25 = fma52hi(res25, a[10], a[14]); // Sum(24)
        res25 = fma52lo(res25, a[11], a[14]); // Sum(25)
        res26 = fma52hi(res26, a[11], a[14]); // Sum(25)
        res26 = fma52lo(res26, a[12], a[14]); // Sum(26)
        res27 = fma52hi(res27, a[12], a[14]); // Sum(26)
        res27 = fma52lo(res27, a[13], a[14]); // Sum(27)
        res28 = fma52hi(res28, a[13], a[14]); // Sum(27)
        res24 = fma52lo(res24, a[9], a[15]);  // Sum(24)
        res25 = fma52hi(res25, a[9], a[15]);  // Sum(24)
        res25 = fma52lo(res25, a[10], a[15]); // Sum(25)
        res26 = fma52hi(res26, a[10], a[15]); // Sum(25)
        res26 = fma52lo(res26, a[11], a[15]); // Sum(26)
        res27 = fma52hi(res27, a[11], a[15]); // Sum(26)
        res27 = fma52lo(res27, a[12], a[15]); // Sum(27)
        res28 = fma52hi(res28, a[12], a[15]); // Sum(27)
        res28 = fma52lo(res28, a[13], a[15]); // Sum(28)
        res29 = fma52hi(res29, a[13], a[15]); // Sum(28)
        res29 = fma52lo(res29, a[14], a[15]); // Sum(29)
        res30 = fma52hi(res30, a[14], a[15]); // Sum(29)
        res24 = fma52lo(res24, a[8], a[16]);  // Sum(24)
        res25 = fma52hi(res25, a[8], a[16]);  // Sum(24)
        res25 = fma52lo(res25, a[9], a[16]);  // Sum(25)
        res26 = fma52hi(res26, a[9], a[16]);  // Sum(25)
        res26 = fma52lo(res26, a[10], a[16]); // Sum(26)
        res27 = fma52hi(res27, a[10], a[16]); // Sum(26)
        res27 = fma52lo(res27, a[11], a[16]); // Sum(27)
        res28 = fma52hi(res28, a[11], a[16]); // Sum(27)
        res28 = fma52lo(res28, a[12], a[16]); // Sum(28)
        res29 = fma52hi(res29, a[12], a[16]); // Sum(28)
        res29 = fma52lo(res29, a[13], a[16]); // Sum(29)
        res30 = fma52hi(res30, a[13], a[16]); // Sum(29)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        idx_curr              = set64(2 + 4 * iter);
        extract_sel_mask_next = cmpeq64_mask(idx_curr, idx_target);
        temp                  = loadstream64(MulTbl[1 + 4 * iter][0]);
        mulb[0]               = _mm512_mask_mov_epi64(mulb[0], extract_sel_mask, temp);
        temp                  = loadstream64(MulTbl[1 + 4 * iter][1]);
        mulb[1]               = _mm512_mask_mov_epi64(mulb[1], extract_sel_mask, temp);
        temp                  = loadstream64(MulTbl[1 + 4 * iter][2]);
        mulb[2]               = _mm512_mask_mov_epi64(mulb[2], extract_sel_mask, temp);
        temp                  = loadstream64(MulTbl[1 + 4 * iter][3]);
        mulb[3]               = _mm512_mask_mov_epi64(mulb[3], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res30 = fma52lo(res30, a[14], a[16]); // Sum(30)
        res31 = fma52hi(res31, a[14], a[16]); // Sum(30)
        res31 = fma52lo(res31, a[15], a[16]); // Sum(31)
        res32 = fma52hi(res32, a[15], a[16]); // Sum(31)
        res24 = fma52lo(res24, a[7], a[17]);  // Sum(24)
        res25 = fma52hi(res25, a[7], a[17]);  // Sum(24)
        res25 = fma52lo(res25, a[8], a[17]);  // Sum(25)
        res26 = fma52hi(res26, a[8], a[17]);  // Sum(25)
        res26 = fma52lo(res26, a[9], a[17]);  // Sum(26)
        res27 = fma52hi(res27, a[9], a[17]);  // Sum(26)
        res27 = fma52lo(res27, a[10], a[17]); // Sum(27)
        res28 = fma52hi(res28, a[10], a[17]); // Sum(27)
        res28 = fma52lo(res28, a[11], a[17]); // Sum(28)
        res29 = fma52hi(res29, a[11], a[17]); // Sum(28)
        res29 = fma52lo(res29, a[12], a[17]); // Sum(29)
        res30 = fma52hi(res30, a[12], a[17]); // Sum(29)
        res30 = fma52lo(res30, a[13], a[17]); // Sum(30)
        res31 = fma52hi(res31, a[13], a[17]); // Sum(30)
        res31 = fma52lo(res31, a[14], a[17]); // Sum(31)
        res32 = fma52hi(res32, a[14], a[17]); // Sum(31)
        res32 = fma52lo(res32, a[15], a[17]); // Sum(32)
        res33 = fma52hi(res33, a[15], a[17]); // Sum(32)
        res33 = fma52lo(res33, a[16], a[17]); // Sum(33)
        res34 = fma52hi(res34, a[16], a[17]); // Sum(33)
        res24 = fma52lo(res24, a[6], a[18]);  // Sum(24)
        res25 = fma52hi(res25, a[6], a[18]);  // Sum(24)
        res25 = fma52lo(res25, a[7], a[18]);  // Sum(25)
        res26 = fma52hi(res26, a[7], a[18]);  // Sum(25)
        res26 = fma52lo(res26, a[8], a[18]);  // Sum(26)
        res27 = fma52hi(res27, a[8], a[18]);  // Sum(26)
        res27 = fma52lo(res27, a[9], a[18]);  // Sum(27)
        res28 = fma52hi(res28, a[9], a[18]);  // Sum(27)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp    = loadstream64(MulTbl[1 + 4 * iter][4]);
        mulb[4] = _mm512_mask_mov_epi64(mulb[4], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[1 + 4 * iter][5]);
        mulb[5] = _mm512_mask_mov_epi64(mulb[5], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[1 + 4 * iter][6]);
        mulb[6] = _mm512_mask_mov_epi64(mulb[6], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[1 + 4 * iter][7]);
        mulb[7] = _mm512_mask_mov_epi64(mulb[7], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res28 = fma52lo(res28, a[10], a[18]); // Sum(28)
        res29 = fma52hi(res29, a[10], a[18]); // Sum(28)
        res29 = fma52lo(res29, a[11], a[18]); // Sum(29)
        res30 = fma52hi(res30, a[11], a[18]); // Sum(29)
        res30 = fma52lo(res30, a[12], a[18]); // Sum(30)
        res31 = fma52hi(res31, a[12], a[18]); // Sum(30)
        res31 = fma52lo(res31, a[13], a[18]); // Sum(31)
        res32 = fma52hi(res32, a[13], a[18]); // Sum(31)
        res32 = fma52lo(res32, a[14], a[18]); // Sum(32)
        res33 = fma52hi(res33, a[14], a[18]); // Sum(32)
        res33 = fma52lo(res33, a[15], a[18]); // Sum(33)
        res34 = fma52hi(res34, a[15], a[18]); // Sum(33)
        res34 = fma52lo(res34, a[16], a[18]); // Sum(34)
        res35 = fma52hi(res35, a[16], a[18]); // Sum(34)
        res35 = fma52lo(res35, a[17], a[18]); // Sum(35)
        res36 = fma52hi(res36, a[17], a[18]); // Sum(35)
        res24 = fma52lo(res24, a[5], a[19]);  // Sum(24)
        res25 = fma52hi(res25, a[5], a[19]);  // Sum(24)
        res25 = fma52lo(res25, a[6], a[19]);  // Sum(25)
        res26 = fma52hi(res26, a[6], a[19]);  // Sum(25)
        res26 = fma52lo(res26, a[7], a[19]);  // Sum(26)
        res27 = fma52hi(res27, a[7], a[19]);  // Sum(26)
        res27 = fma52lo(res27, a[8], a[19]);  // Sum(27)
        res28 = fma52hi(res28, a[8], a[19]);  // Sum(27)
        res28 = fma52lo(res28, a[9], a[19]);  // Sum(28)
        res29 = fma52hi(res29, a[9], a[19]);  // Sum(28)
        res29 = fma52lo(res29, a[10], a[19]); // Sum(29)
        res30 = fma52hi(res30, a[10], a[19]); // Sum(29)
        res30 = fma52lo(res30, a[11], a[19]); // Sum(30)
        res31 = fma52hi(res31, a[11], a[19]); // Sum(30)
        res31 = fma52lo(res31, a[12], a[19]); // Sum(31)
        res32 = fma52hi(res32, a[12], a[19]); // Sum(31)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[1 + 4 * iter][8]);
        mulb[8]  = _mm512_mask_mov_epi64(mulb[8], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[1 + 4 * iter][9]);
        mulb[9]  = _mm512_mask_mov_epi64(mulb[9], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[1 + 4 * iter][10]);
        mulb[10] = _mm512_mask_mov_epi64(mulb[10], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[1 + 4 * iter][11]);
        mulb[11] = _mm512_mask_mov_epi64(mulb[11], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res32 = fma52lo(res32, a[13], a[19]); // Sum(32)
        res33 = fma52hi(res33, a[13], a[19]); // Sum(32)
        res33 = fma52lo(res33, a[14], a[19]); // Sum(33)
        res34 = fma52hi(res34, a[14], a[19]); // Sum(33)
        res34 = fma52lo(res34, a[15], a[19]); // Sum(34)
        res35 = fma52hi(res35, a[15], a[19]); // Sum(34)
        res35 = fma52lo(res35, a[16], a[19]); // Sum(35)
        res36 = fma52hi(res36, a[16], a[19]); // Sum(35)
        res24 = add64(res24, res24);          // Double(24)
        res25 = add64(res25, res25);          // Double(25)
        res26 = add64(res26, res26);          // Double(26)
        res27 = add64(res27, res27);          // Double(27)
        res28 = add64(res28, res28);          // Double(28)
        res29 = add64(res29, res29);          // Double(29)
        res30 = add64(res30, res30);          // Double(30)
        res31 = add64(res31, res31);          // Double(31)
        res32 = add64(res32, res32);          // Double(32)
        res33 = add64(res33, res33);          // Double(33)
        res34 = add64(res34, res34);          // Double(34)
        res35 = add64(res35, res35);          // Double(35)
        res24 = fma52lo(res24, a[12], a[12]); // Add sqr(24)
        res25 = fma52hi(res25, a[12], a[12]); // Add sqr(24)
        res26 = fma52lo(res26, a[13], a[13]); // Add sqr(26)
        res27 = fma52hi(res27, a[13], a[13]); // Add sqr(26)
        res28 = fma52lo(res28, a[14], a[14]); // Add sqr(28)
        res29 = fma52hi(res29, a[14], a[14]); // Add sqr(28)
        res30 = fma52lo(res30, a[15], a[15]); // Add sqr(30)
        res31 = fma52hi(res31, a[15], a[15]); // Add sqr(30)
        res32 = fma52lo(res32, a[16], a[16]); // Add sqr(32)
        res33 = fma52hi(res33, a[16], a[16]); // Add sqr(32)
        res34 = fma52lo(res34, a[17], a[17]); // Add sqr(34)
        res35 = fma52hi(res35, a[17], a[17]); // Add sqr(34)
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[1 + 4 * iter][12]);
        mulb[12] = _mm512_mask_mov_epi64(mulb[12], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[1 + 4 * iter][13]);
        mulb[13] = _mm512_mask_mov_epi64(mulb[13], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[1 + 4 * iter][14]);
        mulb[14] = _mm512_mask_mov_epi64(mulb[14], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[1 + 4 * iter][15]);
        mulb[15] = _mm512_mask_mov_epi64(mulb[15], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res36 = fma52lo(res36, a[17], a[19]); // Sum(36)
        res37 = fma52hi(res37, a[17], a[19]); // Sum(36)
        res37 = fma52lo(res37, a[18], a[19]); // Sum(37)
        res38 = fma52hi(res38, a[18], a[19]); // Sum(37)
        res36 = add64(res36, res36);          // Double(36)
        res37 = add64(res37, res37);          // Double(37)
        res38 = add64(res38, res38);          // Double(38)
        res36 = fma52lo(res36, a[18], a[18]); // Add sqr(36)
        res37 = fma52hi(res37, a[18], a[18]); // Add sqr(36)
        res38 = fma52lo(res38, a[19], a[19]); // Add sqr(38)
        res39 = fma52hi(res39, a[19], a[19]); // Add sqr(38)

        // Begin Reduction
        U64 u0 = mul52lo(res00, mont_constant);

        res00 = fma52lo(res00, u0, m[0]);
        res01 = fma52hi(res01, u0, m[0]);
        res01 = fma52lo(res01, u0, m[1]);
        res02 = fma52hi(res02, u0, m[1]);

        res01  = add64(res01, srli64(res00, DIGIT_SIZE));
        U64 u1 = mul52lo(res01, mont_constant); // early multiplication for the reduction of res01

        res02 = fma52lo(res02, u0, m[2]);
        res03 = fma52hi(res03, u0, m[2]);
        res03 = fma52lo(res03, u0, m[3]);
        res04 = fma52hi(res04, u0, m[3]);
        res04 = fma52lo(res04, u0, m[4]);
        res05 = fma52hi(res05, u0, m[4]);
        res05 = fma52lo(res05, u0, m[5]);
        res06 = fma52hi(res06, u0, m[5]);
        res06 = fma52lo(res06, u0, m[6]);
        res07 = fma52hi(res07, u0, m[6]);
        res07 = fma52lo(res07, u0, m[7]);
        res08 = fma52hi(res08, u0, m[7]);
        res08 = fma52lo(res08, u0, m[8]);
        res09 = fma52hi(res09, u0, m[8]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[1 + 4 * iter][16]);
        mulb[16] = _mm512_mask_mov_epi64(mulb[16], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[1 + 4 * iter][17]);
        mulb[17] = _mm512_mask_mov_epi64(mulb[17], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[1 + 4 * iter][18]);
        mulb[18] = _mm512_mask_mov_epi64(mulb[18], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[1 + 4 * iter][19]);
        mulb[19] = _mm512_mask_mov_epi64(mulb[19], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res09 = fma52lo(res09, u0, m[9]);
        res10 = fma52hi(res10, u0, m[9]);
        res10 = fma52lo(res10, u0, m[10]);
        res11 = fma52hi(res11, u0, m[10]);
        res11 = fma52lo(res11, u0, m[11]);
        res12 = fma52hi(res12, u0, m[11]);
        res12 = fma52lo(res12, u0, m[12]);
        res13 = fma52hi(res13, u0, m[12]);
        res13 = fma52lo(res13, u0, m[13]);
        res14 = fma52hi(res14, u0, m[13]);
        res14 = fma52lo(res14, u0, m[14]);
        res15 = fma52hi(res15, u0, m[14]);
        res15 = fma52lo(res15, u0, m[15]);
        res16 = fma52hi(res16, u0, m[15]);
        res16 = fma52lo(res16, u0, m[16]);
        res17 = fma52hi(res17, u0, m[16]);
        res17 = fma52lo(res17, u0, m[17]);
        res18 = fma52hi(res18, u0, m[17]);
        res18 = fma52lo(res18, u0, m[18]);
        res19 = fma52hi(res19, u0, m[18]);
        res19 = fma52lo(res19, u0, m[19]);
        res20 = fma52hi(res20, u0, m[19]);
        res01 = fma52lo(res01, u1, m[0]);
        res02 = fma52hi(res02, u1, m[0]);
        res02 = fma52lo(res02, u1, m[1]);
        res03 = fma52hi(res03, u1, m[1]);

        res02  = add64(res02, srli64(res01, DIGIT_SIZE));
        U64 u2 = mul52lo(res02, mont_constant); // early multiplication for the reduction of res02

        res03 = fma52lo(res03, u1, m[2]);
        res04 = fma52hi(res04, u1, m[2]);
        res04 = fma52lo(res04, u1, m[3]);
        res05 = fma52hi(res05, u1, m[3]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx    = loadstream64(MulTblx[1 + 4 * iter][0]);
        mulbx[0] = _mm512_mask_mov_epi64(mulbx[0], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[1 + 4 * iter][1]);
        mulbx[1] = _mm512_mask_mov_epi64(mulbx[1], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[1 + 4 * iter][2]);
        mulbx[2] = _mm512_mask_mov_epi64(mulbx[2], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[1 + 4 * iter][3]);
        mulbx[3] = _mm512_mask_mov_epi64(mulbx[3], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res05 = fma52lo(res05, u1, m[4]);
        res06 = fma52hi(res06, u1, m[4]);
        res06 = fma52lo(res06, u1, m[5]);
        res07 = fma52hi(res07, u1, m[5]);
        res07 = fma52lo(res07, u1, m[6]);
        res08 = fma52hi(res08, u1, m[6]);
        res08 = fma52lo(res08, u1, m[7]);
        res09 = fma52hi(res09, u1, m[7]);
        res09 = fma52lo(res09, u1, m[8]);
        res10 = fma52hi(res10, u1, m[8]);
        res10 = fma52lo(res10, u1, m[9]);
        res11 = fma52hi(res11, u1, m[9]);
        res11 = fma52lo(res11, u1, m[10]);
        res12 = fma52hi(res12, u1, m[10]);
        res12 = fma52lo(res12, u1, m[11]);
        res13 = fma52hi(res13, u1, m[11]);
        res13 = fma52lo(res13, u1, m[12]);
        res14 = fma52hi(res14, u1, m[12]);
        res14 = fma52lo(res14, u1, m[13]);
        res15 = fma52hi(res15, u1, m[13]);
        res15 = fma52lo(res15, u1, m[14]);
        res16 = fma52hi(res16, u1, m[14]);
        res16 = fma52lo(res16, u1, m[15]);
        res17 = fma52hi(res17, u1, m[15]);
        res17 = fma52lo(res17, u1, m[16]);
        res18 = fma52hi(res18, u1, m[16]);
        res18 = fma52lo(res18, u1, m[17]);
        res19 = fma52hi(res19, u1, m[17]);
        res19 = fma52lo(res19, u1, m[18]);
        res20 = fma52hi(res20, u1, m[18]);
        res20 = fma52lo(res20, u1, m[19]);
        res21 = fma52hi(res21, u1, m[19]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx    = loadstream64(MulTblx[1 + 4 * iter][4]);
        mulbx[4] = _mm512_mask_mov_epi64(mulbx[4], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[1 + 4 * iter][5]);
        mulbx[5] = _mm512_mask_mov_epi64(mulbx[5], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[1 + 4 * iter][6]);
        mulbx[6] = _mm512_mask_mov_epi64(mulbx[6], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[1 + 4 * iter][7]);
        mulbx[7] = _mm512_mask_mov_epi64(mulbx[7], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res02 = fma52lo(res02, u2, m[0]);
        res03 = fma52hi(res03, u2, m[0]);
        res03 = fma52lo(res03, u2, m[1]);
        res04 = fma52hi(res04, u2, m[1]);

        res03  = add64(res03, srli64(res02, DIGIT_SIZE));
        U64 u3 = mul52lo(res03, mont_constant); // early multiplication for the reduction of res03

        res04 = fma52lo(res04, u2, m[2]);
        res05 = fma52hi(res05, u2, m[2]);
        res05 = fma52lo(res05, u2, m[3]);
        res06 = fma52hi(res06, u2, m[3]);
        res06 = fma52lo(res06, u2, m[4]);
        res07 = fma52hi(res07, u2, m[4]);
        res07 = fma52lo(res07, u2, m[5]);
        res08 = fma52hi(res08, u2, m[5]);
        res08 = fma52lo(res08, u2, m[6]);
        res09 = fma52hi(res09, u2, m[6]);
        res09 = fma52lo(res09, u2, m[7]);
        res10 = fma52hi(res10, u2, m[7]);
        res10 = fma52lo(res10, u2, m[8]);
        res11 = fma52hi(res11, u2, m[8]);
        res11 = fma52lo(res11, u2, m[9]);
        res12 = fma52hi(res12, u2, m[9]);
        res12 = fma52lo(res12, u2, m[10]);
        res13 = fma52hi(res13, u2, m[10]);
        res13 = fma52lo(res13, u2, m[11]);
        res14 = fma52hi(res14, u2, m[11]);
        res14 = fma52lo(res14, u2, m[12]);
        res15 = fma52hi(res15, u2, m[12]);
        res15 = fma52lo(res15, u2, m[13]);
        res16 = fma52hi(res16, u2, m[13]);
        res16 = fma52lo(res16, u2, m[14]);
        res17 = fma52hi(res17, u2, m[14]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx     = loadstream64(MulTblx[1 + 4 * iter][8]);
        mulbx[8]  = _mm512_mask_mov_epi64(mulbx[8], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[1 + 4 * iter][9]);
        mulbx[9]  = _mm512_mask_mov_epi64(mulbx[9], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[1 + 4 * iter][10]);
        mulbx[10] = _mm512_mask_mov_epi64(mulbx[10], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[1 + 4 * iter][11]);
        mulbx[11] = _mm512_mask_mov_epi64(mulbx[11], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res17 = fma52lo(res17, u2, m[15]);
        res18 = fma52hi(res18, u2, m[15]);
        res18 = fma52lo(res18, u2, m[16]);
        res19 = fma52hi(res19, u2, m[16]);
        res19 = fma52lo(res19, u2, m[17]);
        res20 = fma52hi(res20, u2, m[17]);
        res20 = fma52lo(res20, u2, m[18]);
        res21 = fma52hi(res21, u2, m[18]);
        res21 = fma52lo(res21, u2, m[19]);
        res22 = fma52hi(res22, u2, m[19]);
        res03 = fma52lo(res03, u3, m[0]);
        res04 = fma52hi(res04, u3, m[0]);
        res04 = fma52lo(res04, u3, m[1]);
        res05 = fma52hi(res05, u3, m[1]);

        res04  = add64(res04, srli64(res03, DIGIT_SIZE));
        U64 u4 = mul52lo(res04, mont_constant); // early multiplication for the reduction of res04

        res05 = fma52lo(res05, u3, m[2]);
        res06 = fma52hi(res06, u3, m[2]);
        res06 = fma52lo(res06, u3, m[3]);
        res07 = fma52hi(res07, u3, m[3]);
        res07 = fma52lo(res07, u3, m[4]);
        res08 = fma52hi(res08, u3, m[4]);
        res08 = fma52lo(res08, u3, m[5]);
        res09 = fma52hi(res09, u3, m[5]);
        res09 = fma52lo(res09, u3, m[6]);
        res10 = fma52hi(res10, u3, m[6]);
        res10 = fma52lo(res10, u3, m[7]);
        res11 = fma52hi(res11, u3, m[7]);
        res11 = fma52lo(res11, u3, m[8]);
        res12 = fma52hi(res12, u3, m[8]);
        res12 = fma52lo(res12, u3, m[9]);
        res13 = fma52hi(res13, u3, m[9]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx     = loadstream64(MulTblx[1 + 4 * iter][12]);
        mulbx[12] = _mm512_mask_mov_epi64(mulbx[12], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[1 + 4 * iter][13]);
        mulbx[13] = _mm512_mask_mov_epi64(mulbx[13], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[1 + 4 * iter][14]);
        mulbx[14] = _mm512_mask_mov_epi64(mulbx[14], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[1 + 4 * iter][15]);
        mulbx[15] = _mm512_mask_mov_epi64(mulbx[15], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res13 = fma52lo(res13, u3, m[10]);
        res14 = fma52hi(res14, u3, m[10]);
        res14 = fma52lo(res14, u3, m[11]);
        res15 = fma52hi(res15, u3, m[11]);
        res15 = fma52lo(res15, u3, m[12]);
        res16 = fma52hi(res16, u3, m[12]);
        res16 = fma52lo(res16, u3, m[13]);
        res17 = fma52hi(res17, u3, m[13]);
        res17 = fma52lo(res17, u3, m[14]);
        res18 = fma52hi(res18, u3, m[14]);
        res18 = fma52lo(res18, u3, m[15]);
        res19 = fma52hi(res19, u3, m[15]);
        res19 = fma52lo(res19, u3, m[16]);
        res20 = fma52hi(res20, u3, m[16]);
        res20 = fma52lo(res20, u3, m[17]);
        res21 = fma52hi(res21, u3, m[17]);
        res21 = fma52lo(res21, u3, m[18]);
        res22 = fma52hi(res22, u3, m[18]);
        res22 = fma52lo(res22, u3, m[19]);
        res23 = fma52hi(res23, u3, m[19]);
        res04 = fma52lo(res04, u4, m[0]);
        res05 = fma52hi(res05, u4, m[0]);
        res05 = fma52lo(res05, u4, m[1]);
        res06 = fma52hi(res06, u4, m[1]);

        res05  = add64(res05, srli64(res04, DIGIT_SIZE));
        U64 u5 = mul52lo(res05, mont_constant); // early multiplication for the reduction of res05

        res06 = fma52lo(res06, u4, m[2]);
        res07 = fma52hi(res07, u4, m[2]);
        res07 = fma52lo(res07, u4, m[3]);
        res08 = fma52hi(res08, u4, m[3]);
        res08 = fma52lo(res08, u4, m[4]);
        res09 = fma52hi(res09, u4, m[4]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx            = loadstream64(MulTblx[1 + 4 * iter][16]);
        mulbx[16]        = _mm512_mask_mov_epi64(mulbx[16], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[1 + 4 * iter][17]);
        mulbx[17]        = _mm512_mask_mov_epi64(mulbx[17], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[1 + 4 * iter][18]);
        mulbx[18]        = _mm512_mask_mov_epi64(mulbx[18], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[1 + 4 * iter][19]);
        mulbx[19]        = _mm512_mask_mov_epi64(mulbx[19], extract_sel_mask, tempx);
        extract_sel_mask = extract_sel_mask_next;
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res09 = fma52lo(res09, u4, m[5]);
        res10 = fma52hi(res10, u4, m[5]);
        res10 = fma52lo(res10, u4, m[6]);
        res11 = fma52hi(res11, u4, m[6]);
        res11 = fma52lo(res11, u4, m[7]);
        res12 = fma52hi(res12, u4, m[7]);
        res12 = fma52lo(res12, u4, m[8]);
        res13 = fma52hi(res13, u4, m[8]);
        res13 = fma52lo(res13, u4, m[9]);
        res14 = fma52hi(res14, u4, m[9]);
        res14 = fma52lo(res14, u4, m[10]);
        res15 = fma52hi(res15, u4, m[10]);
        res15 = fma52lo(res15, u4, m[11]);
        res16 = fma52hi(res16, u4, m[11]);
        res16 = fma52lo(res16, u4, m[12]);
        res17 = fma52hi(res17, u4, m[12]);
        res17 = fma52lo(res17, u4, m[13]);
        res18 = fma52hi(res18, u4, m[13]);
        res18 = fma52lo(res18, u4, m[14]);
        res19 = fma52hi(res19, u4, m[14]);
        res19 = fma52lo(res19, u4, m[15]);
        res20 = fma52hi(res20, u4, m[15]);
        res20 = fma52lo(res20, u4, m[16]);
        res21 = fma52hi(res21, u4, m[16]);
        res21 = fma52lo(res21, u4, m[17]);
        res22 = fma52hi(res22, u4, m[17]);
        res22 = fma52lo(res22, u4, m[18]);
        res23 = fma52hi(res23, u4, m[18]);
        res23 = fma52lo(res23, u4, m[19]);
        res24 = fma52hi(res24, u4, m[19]);
        res05 = fma52lo(res05, u5, m[0]);
        res06 = fma52hi(res06, u5, m[0]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        idx_curr              = set64(3 + 4 * iter);
        extract_sel_mask_next = cmpeq64_mask(idx_curr, idx_target);
        temp                  = loadstream64(MulTbl[2 + 4 * iter][0]);
        mulb[0]               = _mm512_mask_mov_epi64(mulb[0], extract_sel_mask, temp);
        temp                  = loadstream64(MulTbl[2 + 4 * iter][1]);
        mulb[1]               = _mm512_mask_mov_epi64(mulb[1], extract_sel_mask, temp);
        temp                  = loadstream64(MulTbl[2 + 4 * iter][2]);
        mulb[2]               = _mm512_mask_mov_epi64(mulb[2], extract_sel_mask, temp);
        temp                  = loadstream64(MulTbl[2 + 4 * iter][3]);
        mulb[3]               = _mm512_mask_mov_epi64(mulb[3], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res06 = fma52lo(res06, u5, m[1]);
        res07 = fma52hi(res07, u5, m[1]);

        res06  = add64(res06, srli64(res05, DIGIT_SIZE));
        U64 u6 = mul52lo(res06, mont_constant); // early multiplication for the reduction of res06

        res07 = fma52lo(res07, u5, m[2]);
        res08 = fma52hi(res08, u5, m[2]);
        res08 = fma52lo(res08, u5, m[3]);
        res09 = fma52hi(res09, u5, m[3]);
        res09 = fma52lo(res09, u5, m[4]);
        res10 = fma52hi(res10, u5, m[4]);
        res10 = fma52lo(res10, u5, m[5]);
        res11 = fma52hi(res11, u5, m[5]);
        res11 = fma52lo(res11, u5, m[6]);
        res12 = fma52hi(res12, u5, m[6]);
        res12 = fma52lo(res12, u5, m[7]);
        res13 = fma52hi(res13, u5, m[7]);
        res13 = fma52lo(res13, u5, m[8]);
        res14 = fma52hi(res14, u5, m[8]);
        res14 = fma52lo(res14, u5, m[9]);
        res15 = fma52hi(res15, u5, m[9]);
        res15 = fma52lo(res15, u5, m[10]);
        res16 = fma52hi(res16, u5, m[10]);
        res16 = fma52lo(res16, u5, m[11]);
        res17 = fma52hi(res17, u5, m[11]);
        res17 = fma52lo(res17, u5, m[12]);
        res18 = fma52hi(res18, u5, m[12]);
        res18 = fma52lo(res18, u5, m[13]);
        res19 = fma52hi(res19, u5, m[13]);
        res19 = fma52lo(res19, u5, m[14]);
        res20 = fma52hi(res20, u5, m[14]);
        res20 = fma52lo(res20, u5, m[15]);
        res21 = fma52hi(res21, u5, m[15]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp    = loadstream64(MulTbl[2 + 4 * iter][4]);
        mulb[4] = _mm512_mask_mov_epi64(mulb[4], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[2 + 4 * iter][5]);
        mulb[5] = _mm512_mask_mov_epi64(mulb[5], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[2 + 4 * iter][6]);
        mulb[6] = _mm512_mask_mov_epi64(mulb[6], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[2 + 4 * iter][7]);
        mulb[7] = _mm512_mask_mov_epi64(mulb[7], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res21 = fma52lo(res21, u5, m[16]);
        res22 = fma52hi(res22, u5, m[16]);
        res22 = fma52lo(res22, u5, m[17]);
        res23 = fma52hi(res23, u5, m[17]);
        res23 = fma52lo(res23, u5, m[18]);
        res24 = fma52hi(res24, u5, m[18]);
        res24 = fma52lo(res24, u5, m[19]);
        res25 = fma52hi(res25, u5, m[19]);
        res06 = fma52lo(res06, u6, m[0]);
        res07 = fma52hi(res07, u6, m[0]);
        res07 = fma52lo(res07, u6, m[1]);
        res08 = fma52hi(res08, u6, m[1]);

        res07  = add64(res07, srli64(res06, DIGIT_SIZE));
        U64 u7 = mul52lo(res07, mont_constant); // early multiplication for the reduction of res07

        res08 = fma52lo(res08, u6, m[2]);
        res09 = fma52hi(res09, u6, m[2]);
        res09 = fma52lo(res09, u6, m[3]);
        res10 = fma52hi(res10, u6, m[3]);
        res10 = fma52lo(res10, u6, m[4]);
        res11 = fma52hi(res11, u6, m[4]);
        res11 = fma52lo(res11, u6, m[5]);
        res12 = fma52hi(res12, u6, m[5]);
        res12 = fma52lo(res12, u6, m[6]);
        res13 = fma52hi(res13, u6, m[6]);
        res13 = fma52lo(res13, u6, m[7]);
        res14 = fma52hi(res14, u6, m[7]);
        res14 = fma52lo(res14, u6, m[8]);
        res15 = fma52hi(res15, u6, m[8]);
        res15 = fma52lo(res15, u6, m[9]);
        res16 = fma52hi(res16, u6, m[9]);
        res16 = fma52lo(res16, u6, m[10]);
        res17 = fma52hi(res17, u6, m[10]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[2 + 4 * iter][8]);
        mulb[8]  = _mm512_mask_mov_epi64(mulb[8], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[2 + 4 * iter][9]);
        mulb[9]  = _mm512_mask_mov_epi64(mulb[9], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[2 + 4 * iter][10]);
        mulb[10] = _mm512_mask_mov_epi64(mulb[10], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[2 + 4 * iter][11]);
        mulb[11] = _mm512_mask_mov_epi64(mulb[11], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res17 = fma52lo(res17, u6, m[11]);
        res18 = fma52hi(res18, u6, m[11]);
        res18 = fma52lo(res18, u6, m[12]);
        res19 = fma52hi(res19, u6, m[12]);
        res19 = fma52lo(res19, u6, m[13]);
        res20 = fma52hi(res20, u6, m[13]);
        res20 = fma52lo(res20, u6, m[14]);
        res21 = fma52hi(res21, u6, m[14]);
        res21 = fma52lo(res21, u6, m[15]);
        res22 = fma52hi(res22, u6, m[15]);
        res22 = fma52lo(res22, u6, m[16]);
        res23 = fma52hi(res23, u6, m[16]);
        res23 = fma52lo(res23, u6, m[17]);
        res24 = fma52hi(res24, u6, m[17]);
        res24 = fma52lo(res24, u6, m[18]);
        res25 = fma52hi(res25, u6, m[18]);
        res25 = fma52lo(res25, u6, m[19]);
        res26 = fma52hi(res26, u6, m[19]);
        res07 = fma52lo(res07, u7, m[0]);
        res08 = fma52hi(res08, u7, m[0]);
        res08 = fma52lo(res08, u7, m[1]);
        res09 = fma52hi(res09, u7, m[1]);

        res08  = add64(res08, srli64(res07, DIGIT_SIZE));
        U64 u8 = mul52lo(res08, mont_constant); // early multiplication for the reduction of res08

        res09 = fma52lo(res09, u7, m[2]);
        res10 = fma52hi(res10, u7, m[2]);
        res10 = fma52lo(res10, u7, m[3]);
        res11 = fma52hi(res11, u7, m[3]);
        res11 = fma52lo(res11, u7, m[4]);
        res12 = fma52hi(res12, u7, m[4]);
        res12 = fma52lo(res12, u7, m[5]);
        res13 = fma52hi(res13, u7, m[5]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[2 + 4 * iter][12]);
        mulb[12] = _mm512_mask_mov_epi64(mulb[12], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[2 + 4 * iter][13]);
        mulb[13] = _mm512_mask_mov_epi64(mulb[13], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[2 + 4 * iter][14]);
        mulb[14] = _mm512_mask_mov_epi64(mulb[14], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[2 + 4 * iter][15]);
        mulb[15] = _mm512_mask_mov_epi64(mulb[15], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res13 = fma52lo(res13, u7, m[6]);
        res14 = fma52hi(res14, u7, m[6]);
        res14 = fma52lo(res14, u7, m[7]);
        res15 = fma52hi(res15, u7, m[7]);
        res15 = fma52lo(res15, u7, m[8]);
        res16 = fma52hi(res16, u7, m[8]);
        res16 = fma52lo(res16, u7, m[9]);
        res17 = fma52hi(res17, u7, m[9]);
        res17 = fma52lo(res17, u7, m[10]);
        res18 = fma52hi(res18, u7, m[10]);
        res18 = fma52lo(res18, u7, m[11]);
        res19 = fma52hi(res19, u7, m[11]);
        res19 = fma52lo(res19, u7, m[12]);
        res20 = fma52hi(res20, u7, m[12]);
        res20 = fma52lo(res20, u7, m[13]);
        res21 = fma52hi(res21, u7, m[13]);
        res21 = fma52lo(res21, u7, m[14]);
        res22 = fma52hi(res22, u7, m[14]);
        res22 = fma52lo(res22, u7, m[15]);
        res23 = fma52hi(res23, u7, m[15]);
        res23 = fma52lo(res23, u7, m[16]);
        res24 = fma52hi(res24, u7, m[16]);
        res24 = fma52lo(res24, u7, m[17]);
        res25 = fma52hi(res25, u7, m[17]);
        res25 = fma52lo(res25, u7, m[18]);
        res26 = fma52hi(res26, u7, m[18]);
        res26 = fma52lo(res26, u7, m[19]);
        res27 = fma52hi(res27, u7, m[19]);
        res08 = fma52lo(res08, u8, m[0]);
        res09 = fma52hi(res09, u8, m[0]);
        res09 = fma52lo(res09, u8, m[1]);
        res10 = fma52hi(res10, u8, m[1]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[2 + 4 * iter][16]);
        mulb[16] = _mm512_mask_mov_epi64(mulb[16], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[2 + 4 * iter][17]);
        mulb[17] = _mm512_mask_mov_epi64(mulb[17], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[2 + 4 * iter][18]);
        mulb[18] = _mm512_mask_mov_epi64(mulb[18], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[2 + 4 * iter][19]);
        mulb[19] = _mm512_mask_mov_epi64(mulb[19], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res09  = add64(res09, srli64(res08, DIGIT_SIZE));
        U64 u9 = mul52lo(res09, mont_constant); // early multiplication for the reduction of res09

        res10 = fma52lo(res10, u8, m[2]);
        res11 = fma52hi(res11, u8, m[2]);
        res11 = fma52lo(res11, u8, m[3]);
        res12 = fma52hi(res12, u8, m[3]);
        res12 = fma52lo(res12, u8, m[4]);
        res13 = fma52hi(res13, u8, m[4]);
        res13 = fma52lo(res13, u8, m[5]);
        res14 = fma52hi(res14, u8, m[5]);
        res14 = fma52lo(res14, u8, m[6]);
        res15 = fma52hi(res15, u8, m[6]);
        res15 = fma52lo(res15, u8, m[7]);
        res16 = fma52hi(res16, u8, m[7]);
        res16 = fma52lo(res16, u8, m[8]);
        res17 = fma52hi(res17, u8, m[8]);
        res17 = fma52lo(res17, u8, m[9]);
        res18 = fma52hi(res18, u8, m[9]);
        res18 = fma52lo(res18, u8, m[10]);
        res19 = fma52hi(res19, u8, m[10]);
        res19 = fma52lo(res19, u8, m[11]);
        res20 = fma52hi(res20, u8, m[11]);
        res20 = fma52lo(res20, u8, m[12]);
        res21 = fma52hi(res21, u8, m[12]);
        res21 = fma52lo(res21, u8, m[13]);
        res22 = fma52hi(res22, u8, m[13]);
        res22 = fma52lo(res22, u8, m[14]);
        res23 = fma52hi(res23, u8, m[14]);
        res23 = fma52lo(res23, u8, m[15]);
        res24 = fma52hi(res24, u8, m[15]);
        res24 = fma52lo(res24, u8, m[16]);
        res25 = fma52hi(res25, u8, m[16]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx    = loadstream64(MulTblx[2 + 4 * iter][0]);
        mulbx[0] = _mm512_mask_mov_epi64(mulbx[0], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[2 + 4 * iter][1]);
        mulbx[1] = _mm512_mask_mov_epi64(mulbx[1], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[2 + 4 * iter][2]);
        mulbx[2] = _mm512_mask_mov_epi64(mulbx[2], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[2 + 4 * iter][3]);
        mulbx[3] = _mm512_mask_mov_epi64(mulbx[3], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res25 = fma52lo(res25, u8, m[17]);
        res26 = fma52hi(res26, u8, m[17]);
        res26 = fma52lo(res26, u8, m[18]);
        res27 = fma52hi(res27, u8, m[18]);
        res27 = fma52lo(res27, u8, m[19]);
        res28 = fma52hi(res28, u8, m[19]);
        res09 = fma52lo(res09, u9, m[0]);
        res10 = fma52hi(res10, u9, m[0]);
        res10 = fma52lo(res10, u9, m[1]);
        res11 = fma52hi(res11, u9, m[1]);

        res10   = add64(res10, srli64(res09, DIGIT_SIZE));
        U64 u10 = mul52lo(res10, mont_constant); // early multiplication for the reduction of res10

        res11 = fma52lo(res11, u9, m[2]);
        res12 = fma52hi(res12, u9, m[2]);
        res12 = fma52lo(res12, u9, m[3]);
        res13 = fma52hi(res13, u9, m[3]);
        res13 = fma52lo(res13, u9, m[4]);
        res14 = fma52hi(res14, u9, m[4]);
        res14 = fma52lo(res14, u9, m[5]);
        res15 = fma52hi(res15, u9, m[5]);
        res15 = fma52lo(res15, u9, m[6]);
        res16 = fma52hi(res16, u9, m[6]);
        res16 = fma52lo(res16, u9, m[7]);
        res17 = fma52hi(res17, u9, m[7]);
        res17 = fma52lo(res17, u9, m[8]);
        res18 = fma52hi(res18, u9, m[8]);
        res18 = fma52lo(res18, u9, m[9]);
        res19 = fma52hi(res19, u9, m[9]);
        res19 = fma52lo(res19, u9, m[10]);
        res20 = fma52hi(res20, u9, m[10]);
        res20 = fma52lo(res20, u9, m[11]);
        res21 = fma52hi(res21, u9, m[11]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx    = loadstream64(MulTblx[2 + 4 * iter][4]);
        mulbx[4] = _mm512_mask_mov_epi64(mulbx[4], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[2 + 4 * iter][5]);
        mulbx[5] = _mm512_mask_mov_epi64(mulbx[5], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[2 + 4 * iter][6]);
        mulbx[6] = _mm512_mask_mov_epi64(mulbx[6], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[2 + 4 * iter][7]);
        mulbx[7] = _mm512_mask_mov_epi64(mulbx[7], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res21 = fma52lo(res21, u9, m[12]);
        res22 = fma52hi(res22, u9, m[12]);
        res22 = fma52lo(res22, u9, m[13]);
        res23 = fma52hi(res23, u9, m[13]);
        res23 = fma52lo(res23, u9, m[14]);
        res24 = fma52hi(res24, u9, m[14]);
        res24 = fma52lo(res24, u9, m[15]);
        res25 = fma52hi(res25, u9, m[15]);
        res25 = fma52lo(res25, u9, m[16]);
        res26 = fma52hi(res26, u9, m[16]);
        res26 = fma52lo(res26, u9, m[17]);
        res27 = fma52hi(res27, u9, m[17]);
        res27 = fma52lo(res27, u9, m[18]);
        res28 = fma52hi(res28, u9, m[18]);
        res28 = fma52lo(res28, u9, m[19]);
        res29 = fma52hi(res29, u9, m[19]);
        res10 = fma52lo(res10, u10, m[0]);
        res11 = fma52hi(res11, u10, m[0]);
        res11 = fma52lo(res11, u10, m[1]);
        res12 = fma52hi(res12, u10, m[1]);

        res11   = add64(res11, srli64(res10, DIGIT_SIZE));
        U64 u11 = mul52lo(res11, mont_constant); // early multiplication for the reduction of res11

        res12 = fma52lo(res12, u10, m[2]);
        res13 = fma52hi(res13, u10, m[2]);
        res13 = fma52lo(res13, u10, m[3]);
        res14 = fma52hi(res14, u10, m[3]);
        res14 = fma52lo(res14, u10, m[4]);
        res15 = fma52hi(res15, u10, m[4]);
        res15 = fma52lo(res15, u10, m[5]);
        res16 = fma52hi(res16, u10, m[5]);
        res16 = fma52lo(res16, u10, m[6]);
        res17 = fma52hi(res17, u10, m[6]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx     = loadstream64(MulTblx[2 + 4 * iter][8]);
        mulbx[8]  = _mm512_mask_mov_epi64(mulbx[8], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[2 + 4 * iter][9]);
        mulbx[9]  = _mm512_mask_mov_epi64(mulbx[9], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[2 + 4 * iter][10]);
        mulbx[10] = _mm512_mask_mov_epi64(mulbx[10], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[2 + 4 * iter][11]);
        mulbx[11] = _mm512_mask_mov_epi64(mulbx[11], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res17 = fma52lo(res17, u10, m[7]);
        res18 = fma52hi(res18, u10, m[7]);
        res18 = fma52lo(res18, u10, m[8]);
        res19 = fma52hi(res19, u10, m[8]);
        res19 = fma52lo(res19, u10, m[9]);
        res20 = fma52hi(res20, u10, m[9]);
        res20 = fma52lo(res20, u10, m[10]);
        res21 = fma52hi(res21, u10, m[10]);
        res21 = fma52lo(res21, u10, m[11]);
        res22 = fma52hi(res22, u10, m[11]);
        res22 = fma52lo(res22, u10, m[12]);
        res23 = fma52hi(res23, u10, m[12]);
        res23 = fma52lo(res23, u10, m[13]);
        res24 = fma52hi(res24, u10, m[13]);
        res24 = fma52lo(res24, u10, m[14]);
        res25 = fma52hi(res25, u10, m[14]);
        res25 = fma52lo(res25, u10, m[15]);
        res26 = fma52hi(res26, u10, m[15]);
        res26 = fma52lo(res26, u10, m[16]);
        res27 = fma52hi(res27, u10, m[16]);
        res27 = fma52lo(res27, u10, m[17]);
        res28 = fma52hi(res28, u10, m[17]);
        res28 = fma52lo(res28, u10, m[18]);
        res29 = fma52hi(res29, u10, m[18]);
        res29 = fma52lo(res29, u10, m[19]);
        res30 = fma52hi(res30, u10, m[19]);
        res11 = fma52lo(res11, u11, m[0]);
        res12 = fma52hi(res12, u11, m[0]);
        res12 = fma52lo(res12, u11, m[1]);
        res13 = fma52hi(res13, u11, m[1]);

        res12   = add64(res12, srli64(res11, DIGIT_SIZE));
        U64 u12 = mul52lo(res12, mont_constant); // early multiplication for the reduction of res12
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx     = loadstream64(MulTblx[2 + 4 * iter][12]);
        mulbx[12] = _mm512_mask_mov_epi64(mulbx[12], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[2 + 4 * iter][13]);
        mulbx[13] = _mm512_mask_mov_epi64(mulbx[13], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[2 + 4 * iter][14]);
        mulbx[14] = _mm512_mask_mov_epi64(mulbx[14], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[2 + 4 * iter][15]);
        mulbx[15] = _mm512_mask_mov_epi64(mulbx[15], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res13 = fma52lo(res13, u11, m[2]);
        res14 = fma52hi(res14, u11, m[2]);
        res14 = fma52lo(res14, u11, m[3]);
        res15 = fma52hi(res15, u11, m[3]);
        res15 = fma52lo(res15, u11, m[4]);
        res16 = fma52hi(res16, u11, m[4]);
        res16 = fma52lo(res16, u11, m[5]);
        res17 = fma52hi(res17, u11, m[5]);
        res17 = fma52lo(res17, u11, m[6]);
        res18 = fma52hi(res18, u11, m[6]);
        res18 = fma52lo(res18, u11, m[7]);
        res19 = fma52hi(res19, u11, m[7]);
        res19 = fma52lo(res19, u11, m[8]);
        res20 = fma52hi(res20, u11, m[8]);
        res20 = fma52lo(res20, u11, m[9]);
        res21 = fma52hi(res21, u11, m[9]);
        res21 = fma52lo(res21, u11, m[10]);
        res22 = fma52hi(res22, u11, m[10]);
        res22 = fma52lo(res22, u11, m[11]);
        res23 = fma52hi(res23, u11, m[11]);
        res23 = fma52lo(res23, u11, m[12]);
        res24 = fma52hi(res24, u11, m[12]);
        res24 = fma52lo(res24, u11, m[13]);
        res25 = fma52hi(res25, u11, m[13]);
        res25 = fma52lo(res25, u11, m[14]);
        res26 = fma52hi(res26, u11, m[14]);
        res26 = fma52lo(res26, u11, m[15]);
        res27 = fma52hi(res27, u11, m[15]);
        res27 = fma52lo(res27, u11, m[16]);
        res28 = fma52hi(res28, u11, m[16]);
        res28 = fma52lo(res28, u11, m[17]);
        res29 = fma52hi(res29, u11, m[17]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx            = loadstream64(MulTblx[2 + 4 * iter][16]);
        mulbx[16]        = _mm512_mask_mov_epi64(mulbx[16], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[2 + 4 * iter][17]);
        mulbx[17]        = _mm512_mask_mov_epi64(mulbx[17], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[2 + 4 * iter][18]);
        mulbx[18]        = _mm512_mask_mov_epi64(mulbx[18], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[2 + 4 * iter][19]);
        mulbx[19]        = _mm512_mask_mov_epi64(mulbx[19], extract_sel_mask, tempx);
        extract_sel_mask = extract_sel_mask_next;
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res29 = fma52lo(res29, u11, m[18]);
        res30 = fma52hi(res30, u11, m[18]);
        res30 = fma52lo(res30, u11, m[19]);
        res31 = fma52hi(res31, u11, m[19]);
        res12 = fma52lo(res12, u12, m[0]);
        res13 = fma52hi(res13, u12, m[0]);
        res13 = fma52lo(res13, u12, m[1]);
        res14 = fma52hi(res14, u12, m[1]);

        res13   = add64(res13, srli64(res12, DIGIT_SIZE));
        U64 u13 = mul52lo(res13, mont_constant); // early multiplication for the reduction of res13

        res14 = fma52lo(res14, u12, m[2]);
        res15 = fma52hi(res15, u12, m[2]);
        res15 = fma52lo(res15, u12, m[3]);
        res16 = fma52hi(res16, u12, m[3]);
        res16 = fma52lo(res16, u12, m[4]);
        res17 = fma52hi(res17, u12, m[4]);
        res17 = fma52lo(res17, u12, m[5]);
        res18 = fma52hi(res18, u12, m[5]);
        res18 = fma52lo(res18, u12, m[6]);
        res19 = fma52hi(res19, u12, m[6]);
        res19 = fma52lo(res19, u12, m[7]);
        res20 = fma52hi(res20, u12, m[7]);
        res20 = fma52lo(res20, u12, m[8]);
        res21 = fma52hi(res21, u12, m[8]);
        res21 = fma52lo(res21, u12, m[9]);
        res22 = fma52hi(res22, u12, m[9]);
        res22 = fma52lo(res22, u12, m[10]);
        res23 = fma52hi(res23, u12, m[10]);
        res23 = fma52lo(res23, u12, m[11]);
        res24 = fma52hi(res24, u12, m[11]);
        res24 = fma52lo(res24, u12, m[12]);
        res25 = fma52hi(res25, u12, m[12]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        idx_curr              = set64(4 + 4 * iter);
        extract_sel_mask_next = cmpeq64_mask(idx_curr, idx_target);
        temp                  = loadstream64(MulTbl[3 + 4 * iter][0]);
        mulb[0]               = _mm512_mask_mov_epi64(mulb[0], extract_sel_mask, temp);
        temp                  = loadstream64(MulTbl[3 + 4 * iter][1]);
        mulb[1]               = _mm512_mask_mov_epi64(mulb[1], extract_sel_mask, temp);
        temp                  = loadstream64(MulTbl[3 + 4 * iter][2]);
        mulb[2]               = _mm512_mask_mov_epi64(mulb[2], extract_sel_mask, temp);
        temp                  = loadstream64(MulTbl[3 + 4 * iter][3]);
        mulb[3]               = _mm512_mask_mov_epi64(mulb[3], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res25 = fma52lo(res25, u12, m[13]);
        res26 = fma52hi(res26, u12, m[13]);
        res26 = fma52lo(res26, u12, m[14]);
        res27 = fma52hi(res27, u12, m[14]);
        res27 = fma52lo(res27, u12, m[15]);
        res28 = fma52hi(res28, u12, m[15]);
        res28 = fma52lo(res28, u12, m[16]);
        res29 = fma52hi(res29, u12, m[16]);
        res29 = fma52lo(res29, u12, m[17]);
        res30 = fma52hi(res30, u12, m[17]);
        res30 = fma52lo(res30, u12, m[18]);
        res31 = fma52hi(res31, u12, m[18]);
        res31 = fma52lo(res31, u12, m[19]);
        res32 = fma52hi(res32, u12, m[19]);
        res13 = fma52lo(res13, u13, m[0]);
        res14 = fma52hi(res14, u13, m[0]);
        res14 = fma52lo(res14, u13, m[1]);
        res15 = fma52hi(res15, u13, m[1]);

        res14   = add64(res14, srli64(res13, DIGIT_SIZE));
        U64 u14 = mul52lo(res14, mont_constant); // early multiplication for the reduction of res14

        res15 = fma52lo(res15, u13, m[2]);
        res16 = fma52hi(res16, u13, m[2]);
        res16 = fma52lo(res16, u13, m[3]);
        res17 = fma52hi(res17, u13, m[3]);
        res17 = fma52lo(res17, u13, m[4]);
        res18 = fma52hi(res18, u13, m[4]);
        res18 = fma52lo(res18, u13, m[5]);
        res19 = fma52hi(res19, u13, m[5]);
        res19 = fma52lo(res19, u13, m[6]);
        res20 = fma52hi(res20, u13, m[6]);
        res20 = fma52lo(res20, u13, m[7]);
        res21 = fma52hi(res21, u13, m[7]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp    = loadstream64(MulTbl[3 + 4 * iter][4]);
        mulb[4] = _mm512_mask_mov_epi64(mulb[4], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[3 + 4 * iter][5]);
        mulb[5] = _mm512_mask_mov_epi64(mulb[5], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[3 + 4 * iter][6]);
        mulb[6] = _mm512_mask_mov_epi64(mulb[6], extract_sel_mask, temp);
        temp    = loadstream64(MulTbl[3 + 4 * iter][7]);
        mulb[7] = _mm512_mask_mov_epi64(mulb[7], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res21 = fma52lo(res21, u13, m[8]);
        res22 = fma52hi(res22, u13, m[8]);
        res22 = fma52lo(res22, u13, m[9]);
        res23 = fma52hi(res23, u13, m[9]);
        res23 = fma52lo(res23, u13, m[10]);
        res24 = fma52hi(res24, u13, m[10]);
        res24 = fma52lo(res24, u13, m[11]);
        res25 = fma52hi(res25, u13, m[11]);
        res25 = fma52lo(res25, u13, m[12]);
        res26 = fma52hi(res26, u13, m[12]);
        res26 = fma52lo(res26, u13, m[13]);
        res27 = fma52hi(res27, u13, m[13]);
        res27 = fma52lo(res27, u13, m[14]);
        res28 = fma52hi(res28, u13, m[14]);
        res28 = fma52lo(res28, u13, m[15]);
        res29 = fma52hi(res29, u13, m[15]);
        res29 = fma52lo(res29, u13, m[16]);
        res30 = fma52hi(res30, u13, m[16]);
        res30 = fma52lo(res30, u13, m[17]);
        res31 = fma52hi(res31, u13, m[17]);
        res31 = fma52lo(res31, u13, m[18]);
        res32 = fma52hi(res32, u13, m[18]);
        res32 = fma52lo(res32, u13, m[19]);
        res33 = fma52hi(res33, u13, m[19]);
        res14 = fma52lo(res14, u14, m[0]);
        res15 = fma52hi(res15, u14, m[0]);
        res15 = fma52lo(res15, u14, m[1]);
        res16 = fma52hi(res16, u14, m[1]);

        res15   = add64(res15, srli64(res14, DIGIT_SIZE));
        U64 u15 = mul52lo(res15, mont_constant); // early multiplication for the reduction of res15

        res16 = fma52lo(res16, u14, m[2]);
        res17 = fma52hi(res17, u14, m[2]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[3 + 4 * iter][8]);
        mulb[8]  = _mm512_mask_mov_epi64(mulb[8], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[3 + 4 * iter][9]);
        mulb[9]  = _mm512_mask_mov_epi64(mulb[9], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[3 + 4 * iter][10]);
        mulb[10] = _mm512_mask_mov_epi64(mulb[10], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[3 + 4 * iter][11]);
        mulb[11] = _mm512_mask_mov_epi64(mulb[11], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res17 = fma52lo(res17, u14, m[3]);
        res18 = fma52hi(res18, u14, m[3]);
        res18 = fma52lo(res18, u14, m[4]);
        res19 = fma52hi(res19, u14, m[4]);
        res19 = fma52lo(res19, u14, m[5]);
        res20 = fma52hi(res20, u14, m[5]);
        res20 = fma52lo(res20, u14, m[6]);
        res21 = fma52hi(res21, u14, m[6]);
        res21 = fma52lo(res21, u14, m[7]);
        res22 = fma52hi(res22, u14, m[7]);
        res22 = fma52lo(res22, u14, m[8]);
        res23 = fma52hi(res23, u14, m[8]);
        res23 = fma52lo(res23, u14, m[9]);
        res24 = fma52hi(res24, u14, m[9]);
        res24 = fma52lo(res24, u14, m[10]);
        res25 = fma52hi(res25, u14, m[10]);
        res25 = fma52lo(res25, u14, m[11]);
        res26 = fma52hi(res26, u14, m[11]);
        res26 = fma52lo(res26, u14, m[12]);
        res27 = fma52hi(res27, u14, m[12]);
        res27 = fma52lo(res27, u14, m[13]);
        res28 = fma52hi(res28, u14, m[13]);
        res28 = fma52lo(res28, u14, m[14]);
        res29 = fma52hi(res29, u14, m[14]);
        res29 = fma52lo(res29, u14, m[15]);
        res30 = fma52hi(res30, u14, m[15]);
        res30 = fma52lo(res30, u14, m[16]);
        res31 = fma52hi(res31, u14, m[16]);
        res31 = fma52lo(res31, u14, m[17]);
        res32 = fma52hi(res32, u14, m[17]);
        res32 = fma52lo(res32, u14, m[18]);
        res33 = fma52hi(res33, u14, m[18]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[3 + 4 * iter][12]);
        mulb[12] = _mm512_mask_mov_epi64(mulb[12], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[3 + 4 * iter][13]);
        mulb[13] = _mm512_mask_mov_epi64(mulb[13], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[3 + 4 * iter][14]);
        mulb[14] = _mm512_mask_mov_epi64(mulb[14], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[3 + 4 * iter][15]);
        mulb[15] = _mm512_mask_mov_epi64(mulb[15], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res33 = fma52lo(res33, u14, m[19]);
        res34 = fma52hi(res34, u14, m[19]);
        res15 = fma52lo(res15, u15, m[0]);
        res16 = fma52hi(res16, u15, m[0]);
        res16 = fma52lo(res16, u15, m[1]);
        res17 = fma52hi(res17, u15, m[1]);

        res16   = add64(res16, srli64(res15, DIGIT_SIZE));
        U64 u16 = mul52lo(res16, mont_constant); // early multiplication for the reduction of res16

        res17 = fma52lo(res17, u15, m[2]);
        res18 = fma52hi(res18, u15, m[2]);
        res18 = fma52lo(res18, u15, m[3]);
        res19 = fma52hi(res19, u15, m[3]);
        res19 = fma52lo(res19, u15, m[4]);
        res20 = fma52hi(res20, u15, m[4]);
        res20 = fma52lo(res20, u15, m[5]);
        res21 = fma52hi(res21, u15, m[5]);
        res21 = fma52lo(res21, u15, m[6]);
        res22 = fma52hi(res22, u15, m[6]);
        res22 = fma52lo(res22, u15, m[7]);
        res23 = fma52hi(res23, u15, m[7]);
        res23 = fma52lo(res23, u15, m[8]);
        res24 = fma52hi(res24, u15, m[8]);
        res24 = fma52lo(res24, u15, m[9]);
        res25 = fma52hi(res25, u15, m[9]);
        res25 = fma52lo(res25, u15, m[10]);
        res26 = fma52hi(res26, u15, m[10]);
        res26 = fma52lo(res26, u15, m[11]);
        res27 = fma52hi(res27, u15, m[11]);
        res27 = fma52lo(res27, u15, m[12]);
        res28 = fma52hi(res28, u15, m[12]);
        res28 = fma52lo(res28, u15, m[13]);
        res29 = fma52hi(res29, u15, m[13]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        temp     = loadstream64(MulTbl[3 + 4 * iter][16]);
        mulb[16] = _mm512_mask_mov_epi64(mulb[16], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[3 + 4 * iter][17]);
        mulb[17] = _mm512_mask_mov_epi64(mulb[17], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[3 + 4 * iter][18]);
        mulb[18] = _mm512_mask_mov_epi64(mulb[18], extract_sel_mask, temp);
        temp     = loadstream64(MulTbl[3 + 4 * iter][19]);
        mulb[19] = _mm512_mask_mov_epi64(mulb[19], extract_sel_mask, temp);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res29 = fma52lo(res29, u15, m[14]);
        res30 = fma52hi(res30, u15, m[14]);
        res30 = fma52lo(res30, u15, m[15]);
        res31 = fma52hi(res31, u15, m[15]);
        res31 = fma52lo(res31, u15, m[16]);
        res32 = fma52hi(res32, u15, m[16]);
        res32 = fma52lo(res32, u15, m[17]);
        res33 = fma52hi(res33, u15, m[17]);
        res33 = fma52lo(res33, u15, m[18]);
        res34 = fma52hi(res34, u15, m[18]);
        res34 = fma52lo(res34, u15, m[19]);
        res35 = fma52hi(res35, u15, m[19]);
        res16 = fma52lo(res16, u16, m[0]);
        res17 = fma52hi(res17, u16, m[0]);
        res17 = fma52lo(res17, u16, m[1]);
        res18 = fma52hi(res18, u16, m[1]);

        res17   = add64(res17, srli64(res16, DIGIT_SIZE));
        U64 u17 = mul52lo(res17, mont_constant); // early multiplication for the reduction of res17

        res18 = fma52lo(res18, u16, m[2]);
        res19 = fma52hi(res19, u16, m[2]);
        res19 = fma52lo(res19, u16, m[3]);
        res20 = fma52hi(res20, u16, m[3]);
        res20 = fma52lo(res20, u16, m[4]);
        res21 = fma52hi(res21, u16, m[4]);
        res21 = fma52lo(res21, u16, m[5]);
        res22 = fma52hi(res22, u16, m[5]);
        res22 = fma52lo(res22, u16, m[6]);
        res23 = fma52hi(res23, u16, m[6]);
        res23 = fma52lo(res23, u16, m[7]);
        res24 = fma52hi(res24, u16, m[7]);
        res24 = fma52lo(res24, u16, m[8]);
        res25 = fma52hi(res25, u16, m[8]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx    = loadstream64(MulTblx[3 + 4 * iter][0]);
        mulbx[0] = _mm512_mask_mov_epi64(mulbx[0], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[3 + 4 * iter][1]);
        mulbx[1] = _mm512_mask_mov_epi64(mulbx[1], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[3 + 4 * iter][2]);
        mulbx[2] = _mm512_mask_mov_epi64(mulbx[2], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[3 + 4 * iter][3]);
        mulbx[3] = _mm512_mask_mov_epi64(mulbx[3], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res25 = fma52lo(res25, u16, m[9]);
        res26 = fma52hi(res26, u16, m[9]);
        res26 = fma52lo(res26, u16, m[10]);
        res27 = fma52hi(res27, u16, m[10]);
        res27 = fma52lo(res27, u16, m[11]);
        res28 = fma52hi(res28, u16, m[11]);
        res28 = fma52lo(res28, u16, m[12]);
        res29 = fma52hi(res29, u16, m[12]);
        res29 = fma52lo(res29, u16, m[13]);
        res30 = fma52hi(res30, u16, m[13]);
        res30 = fma52lo(res30, u16, m[14]);
        res31 = fma52hi(res31, u16, m[14]);
        res31 = fma52lo(res31, u16, m[15]);
        res32 = fma52hi(res32, u16, m[15]);
        res32 = fma52lo(res32, u16, m[16]);
        res33 = fma52hi(res33, u16, m[16]);
        res33 = fma52lo(res33, u16, m[17]);
        res34 = fma52hi(res34, u16, m[17]);
        res34 = fma52lo(res34, u16, m[18]);
        res35 = fma52hi(res35, u16, m[18]);
        res35 = fma52lo(res35, u16, m[19]);
        res36 = fma52hi(res36, u16, m[19]);
        res17 = fma52lo(res17, u17, m[0]);
        res18 = fma52hi(res18, u17, m[0]);
        res18 = fma52lo(res18, u17, m[1]);
        res19 = fma52hi(res19, u17, m[1]);

        res18   = add64(res18, srli64(res17, DIGIT_SIZE));
        U64 u18 = mul52lo(res18, mont_constant); // early multiplication for the reduction of res18

        res19 = fma52lo(res19, u17, m[2]);
        res20 = fma52hi(res20, u17, m[2]);
        res20 = fma52lo(res20, u17, m[3]);
        res21 = fma52hi(res21, u17, m[3]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx    = loadstream64(MulTblx[3 + 4 * iter][4]);
        mulbx[4] = _mm512_mask_mov_epi64(mulbx[4], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[3 + 4 * iter][5]);
        mulbx[5] = _mm512_mask_mov_epi64(mulbx[5], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[3 + 4 * iter][6]);
        mulbx[6] = _mm512_mask_mov_epi64(mulbx[6], extract_sel_mask, tempx);
        tempx    = loadstream64(MulTblx[3 + 4 * iter][7]);
        mulbx[7] = _mm512_mask_mov_epi64(mulbx[7], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res21 = fma52lo(res21, u17, m[4]);
        res22 = fma52hi(res22, u17, m[4]);
        res22 = fma52lo(res22, u17, m[5]);
        res23 = fma52hi(res23, u17, m[5]);
        res23 = fma52lo(res23, u17, m[6]);
        res24 = fma52hi(res24, u17, m[6]);
        res24 = fma52lo(res24, u17, m[7]);
        res25 = fma52hi(res25, u17, m[7]);
        res25 = fma52lo(res25, u17, m[8]);
        res26 = fma52hi(res26, u17, m[8]);
        res26 = fma52lo(res26, u17, m[9]);
        res27 = fma52hi(res27, u17, m[9]);
        res27 = fma52lo(res27, u17, m[10]);
        res28 = fma52hi(res28, u17, m[10]);
        res28 = fma52lo(res28, u17, m[11]);
        res29 = fma52hi(res29, u17, m[11]);
        res29 = fma52lo(res29, u17, m[12]);
        res30 = fma52hi(res30, u17, m[12]);
        res30 = fma52lo(res30, u17, m[13]);
        res31 = fma52hi(res31, u17, m[13]);
        res31 = fma52lo(res31, u17, m[14]);
        res32 = fma52hi(res32, u17, m[14]);
        res32 = fma52lo(res32, u17, m[15]);
        res33 = fma52hi(res33, u17, m[15]);
        res33 = fma52lo(res33, u17, m[16]);
        res34 = fma52hi(res34, u17, m[16]);
        res34 = fma52lo(res34, u17, m[17]);
        res35 = fma52hi(res35, u17, m[17]);
        res35 = fma52lo(res35, u17, m[18]);
        res36 = fma52hi(res36, u17, m[18]);
        res36 = fma52lo(res36, u17, m[19]);
        res37 = fma52hi(res37, u17, m[19]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx     = loadstream64(MulTblx[3 + 4 * iter][8]);
        mulbx[8]  = _mm512_mask_mov_epi64(mulbx[8], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[3 + 4 * iter][9]);
        mulbx[9]  = _mm512_mask_mov_epi64(mulbx[9], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[3 + 4 * iter][10]);
        mulbx[10] = _mm512_mask_mov_epi64(mulbx[10], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[3 + 4 * iter][11]);
        mulbx[11] = _mm512_mask_mov_epi64(mulbx[11], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res18 = fma52lo(res18, u18, m[0]);
        res19 = fma52hi(res19, u18, m[0]);
        res19 = fma52lo(res19, u18, m[1]);
        res20 = fma52hi(res20, u18, m[1]);

        res19   = add64(res19, srli64(res18, DIGIT_SIZE));
        U64 u19 = mul52lo(res19, mont_constant); // early multiplication for the reduction of res19

        res20 = fma52lo(res20, u18, m[2]);
        res21 = fma52hi(res21, u18, m[2]);
        res21 = fma52lo(res21, u18, m[3]);
        res22 = fma52hi(res22, u18, m[3]);
        res22 = fma52lo(res22, u18, m[4]);
        res23 = fma52hi(res23, u18, m[4]);
        res23 = fma52lo(res23, u18, m[5]);
        res24 = fma52hi(res24, u18, m[5]);
        res24 = fma52lo(res24, u18, m[6]);
        res25 = fma52hi(res25, u18, m[6]);
        res25 = fma52lo(res25, u18, m[7]);
        res26 = fma52hi(res26, u18, m[7]);
        res26 = fma52lo(res26, u18, m[8]);
        res27 = fma52hi(res27, u18, m[8]);
        res27 = fma52lo(res27, u18, m[9]);
        res28 = fma52hi(res28, u18, m[9]);
        res28 = fma52lo(res28, u18, m[10]);
        res29 = fma52hi(res29, u18, m[10]);
        res29 = fma52lo(res29, u18, m[11]);
        res30 = fma52hi(res30, u18, m[11]);
        res30 = fma52lo(res30, u18, m[12]);
        res31 = fma52hi(res31, u18, m[12]);
        res31 = fma52lo(res31, u18, m[13]);
        res32 = fma52hi(res32, u18, m[13]);
        res32 = fma52lo(res32, u18, m[14]);
        res33 = fma52hi(res33, u18, m[14]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx     = loadstream64(MulTblx[3 + 4 * iter][12]);
        mulbx[12] = _mm512_mask_mov_epi64(mulbx[12], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[3 + 4 * iter][13]);
        mulbx[13] = _mm512_mask_mov_epi64(mulbx[13], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[3 + 4 * iter][14]);
        mulbx[14] = _mm512_mask_mov_epi64(mulbx[14], extract_sel_mask, tempx);
        tempx     = loadstream64(MulTblx[3 + 4 * iter][15]);
        mulbx[15] = _mm512_mask_mov_epi64(mulbx[15], extract_sel_mask, tempx);
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res33 = fma52lo(res33, u18, m[15]);
        res34 = fma52hi(res34, u18, m[15]);
        res34 = fma52lo(res34, u18, m[16]);
        res35 = fma52hi(res35, u18, m[16]);
        res35 = fma52lo(res35, u18, m[17]);
        res36 = fma52hi(res36, u18, m[17]);
        res36 = fma52lo(res36, u18, m[18]);
        res37 = fma52hi(res37, u18, m[18]);
        res37 = fma52lo(res37, u18, m[19]);
        res38 = fma52hi(res38, u18, m[19]);
        res19 = fma52lo(res19, u19, m[0]);
        res20 = fma52hi(res20, u19, m[0]);
        res20 = fma52lo(res20, u19, m[1]);
        res21 = fma52hi(res21, u19, m[1]);
        res20 = add64(res20, srli64(res19, DIGIT_SIZE));
        res21 = fma52lo(res21, u19, m[2]);
        res22 = fma52hi(res22, u19, m[2]);
        res22 = fma52lo(res22, u19, m[3]);
        res23 = fma52hi(res23, u19, m[3]);
        res23 = fma52lo(res23, u19, m[4]);
        res24 = fma52hi(res24, u19, m[4]);
        res24 = fma52lo(res24, u19, m[5]);
        res25 = fma52hi(res25, u19, m[5]);
        res25 = fma52lo(res25, u19, m[6]);
        res26 = fma52hi(res26, u19, m[6]);
        res26 = fma52lo(res26, u19, m[7]);
        res27 = fma52hi(res27, u19, m[7]);
        res27 = fma52lo(res27, u19, m[8]);
        res28 = fma52hi(res28, u19, m[8]);
        res28 = fma52lo(res28, u19, m[9]);
        res29 = fma52hi(res29, u19, m[9]);
        res29 = fma52lo(res29, u19, m[10]);
        //*******END SQUARING CODE SEGMENT**************//

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        tempx            = loadstream64(MulTblx[3 + 4 * iter][16]);
        mulbx[16]        = _mm512_mask_mov_epi64(mulbx[16], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[3 + 4 * iter][17]);
        mulbx[17]        = _mm512_mask_mov_epi64(mulbx[17], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[3 + 4 * iter][18]);
        mulbx[18]        = _mm512_mask_mov_epi64(mulbx[18], extract_sel_mask, tempx);
        tempx            = loadstream64(MulTblx[3 + 4 * iter][19]);
        mulbx[19]        = _mm512_mask_mov_epi64(mulbx[19], extract_sel_mask, tempx);
        extract_sel_mask = extract_sel_mask_next;
        //*******END EXTRACTION CODE SEGMENT******************************//

        //*******BEGIN SQUARING CODE SEGMENT************//
        res30 = fma52hi(res30, u19, m[10]);
        res30 = fma52lo(res30, u19, m[11]);
        res31 = fma52hi(res31, u19, m[11]);
        res31 = fma52lo(res31, u19, m[12]);
        res32 = fma52hi(res32, u19, m[12]);
        res32 = fma52lo(res32, u19, m[13]);
        res33 = fma52hi(res33, u19, m[13]);
        res33 = fma52lo(res33, u19, m[14]);
        res34 = fma52hi(res34, u19, m[14]);
        res34 = fma52lo(res34, u19, m[15]);
        res35 = fma52hi(res35, u19, m[15]);
        res35 = fma52lo(res35, u19, m[16]);
        res36 = fma52hi(res36, u19, m[16]);
        res36 = fma52lo(res36, u19, m[17]);
        res37 = fma52hi(res37, u19, m[17]);
        res37 = fma52lo(res37, u19, m[18]);
        res38 = fma52hi(res38, u19, m[18]);
        res38 = fma52lo(res38, u19, m[19]);
        res39 = fma52hi(res39, u19, m[19]);

        // Normalization
        // We do not need to zero out the top bits
        // They will not be used by the fma53lo/hi instructios
        r[0]  = res20;
        res21 = add64(res21, srli64(res20, DIGIT_SIZE));
        r[1]  = res21;
        res22 = add64(res22, srli64(res21, DIGIT_SIZE));
        r[2]  = res22;
        res23 = add64(res23, srli64(res22, DIGIT_SIZE));
        r[3]  = res23;
        res24 = add64(res24, srli64(res23, DIGIT_SIZE));
        r[4]  = res24;
        res25 = add64(res25, srli64(res24, DIGIT_SIZE));
        r[5]  = res25;
        res26 = add64(res26, srli64(res25, DIGIT_SIZE));
        r[6]  = res26;
        res27 = add64(res27, srli64(res26, DIGIT_SIZE));
        r[7]  = res27;
        res28 = add64(res28, srli64(res27, DIGIT_SIZE));
        r[8]  = res28;
        res29 = add64(res29, srli64(res28, DIGIT_SIZE));
        r[9]  = res29;
        res30 = add64(res30, srli64(res29, DIGIT_SIZE));
        r[10] = res30;
        res31 = add64(res31, srli64(res30, DIGIT_SIZE));
        r[11] = res31;
        res32 = add64(res32, srli64(res31, DIGIT_SIZE));
        r[12] = res32;
        res33 = add64(res33, srli64(res32, DIGIT_SIZE));
        r[13] = res33;
        res34 = add64(res34, srli64(res33, DIGIT_SIZE));
        r[14] = res34;
        res35 = add64(res35, srli64(res34, DIGIT_SIZE));
        r[15] = res35;
        res36 = add64(res36, srli64(res35, DIGIT_SIZE));
        r[16] = res36;
        res37 = add64(res37, srli64(res36, DIGIT_SIZE));
        r[17] = res37;
        res38 = add64(res38, srli64(res37, DIGIT_SIZE));
        r[18] = res38;
        res39 = add64(res39, srli64(res38, DIGIT_SIZE));
        r[19] = res39;
        a     = (U64*)out_mb;
        //*******END SQUARING CODE SEGMENT**************//
    }
}

#endif /* #if (_MBX>=_MBX_K1) */
