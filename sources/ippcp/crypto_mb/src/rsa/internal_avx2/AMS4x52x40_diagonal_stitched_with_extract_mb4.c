/*************************************************************************
 * Copyright (C) 2024 Intel Corporation
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

#if ((_MBX == _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

#include <internal/rsa/avxifma_extract_multiplier.h>

void AMS4x52x40_diagonal_stitched_with_extract_mb4(int64u* out_mb,
                                                   U64* mulb,
                                                   U64* mulbx,
                                                   const int64u* inpA_mb,
                                                   const int64u* inpM_mb,
                                                   const int64u* k0_mb,
                                                   int64u MulTbl[][redLen4K][4],
                                                   int64u MulTblx[][redLen4K][4],
                                                   const __m256i idx_target0)
{
    const int N             = 40;
    const size_t N_x4_sz    = (N * 4 * sizeof(uint64_t));
    const __m256i* pMulTbl  = (const __m256i*)&MulTbl[0][0];
    const __m256i* pMulTblx = (const __m256i*)&MulTblx[0][0];

    for (int iter = 0; iter < 4; ++iter) {
        /* square */
        AMS52x40_diagonal_mb4(out_mb, inpA_mb, inpM_mb, k0_mb);
        inpA_mb = out_mb;

        //*******BEGIN EXTRACTION CODE SEGMENT****************************//
        extract_mb4((__m256i*)mulb, pMulTbl, iter, idx_target0, N);
        extract_mb4((__m256i*)mulbx, pMulTblx, iter, idx_target0, N);
        pMulTbl += ((4 * N_x4_sz) / sizeof(__m256i));
        pMulTblx += ((4 * N_x4_sz) / sizeof(__m256i));
        //*******END EXTRACTION CODE SEGMENT******************************//
    }
}

#endif //#if ((_MBX == _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
