/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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

#include <internal/sm2/ifma_arith_sm2.h>

#if (_MBX >= _MBX_K1)

/* Constants */
#define LEN52 NUMBER_OF_DIGITS(256, DIGIT_SIZE)

/*
// EC SM2 prime base point order
// in 2^52 radix
*/
__ALIGN64 static const int64u nsm2_mb[LEN52][8] = { { REP8_DECL(0x000bf40939d54123) },
                                                    { REP8_DECL(0x0006b21c6052b53b) },
                                                    { REP8_DECL(0x000fffffff7203df) },
                                                    { REP8_DECL(0x000fffffffffffff) },
                                                    { REP8_DECL(0x0000fffffffeffff) } };

__ALIGN64 static const int64u nsm2x2_mb[LEN52][8] = { { REP8_DECL(0x0007e81273aa8246) },
                                                      { REP8_DECL(0x000d6438c0a56a77) },
                                                      { REP8_DECL(0x000ffffffee407be) },
                                                      { REP8_DECL(0x000fffffffffffff) },
                                                      { REP8_DECL(0x0001fffffffdffff) } };

/* k0 = -( (1/nsm2 mod 2^DIGIT_SIZE) ) mod 2^DIGIT_SIZE */
__ALIGN64 static const int64u nsm2_k0_mb[8] = { REP8_DECL(0x000f9e8872350975) };

/* to Montgomery conversion constant
// rr = 2^((LEN52*DIGIT_SIZE)*2) mod nsm2
*/
__ALIGN64 static const int64u nsm2_rr_mb[LEN52][8] = { { REP8_DECL(0x000c16674a517de6) },
                                                       { REP8_DECL(0x000507a6e5f7c418) },
                                                       { REP8_DECL(0x000fe0d44507dc1c) },
                                                       { REP8_DECL(0x0003b620fc84c3af) },
                                                       { REP8_DECL(0x0000b5e412c02b3d) } };

/*=====================================================================

 Specialized single operations in nsm2 - sqr & mul

=====================================================================*/
EXTERN_C U64* MB_FUNC_NAME(ifma_nsm2_)(void) { return (U64*)nsm2_mb; }

void MB_FUNC_NAME(ifma_ams52_nsm2_)(U64 r[], const U64 a[])
{
    MB_FUNC_NAME(ifma_ams52x5_)(r, a, (U64*)nsm2_mb, nsm2_k0_mb);
}

void MB_FUNC_NAME(ifma_amm52_nsm2_)(U64 r[], const U64 a[], const U64 b[])
{
    MB_FUNC_NAME(ifma_amm52x5_)(r, a, b, (U64*)nsm2_mb, nsm2_k0_mb);
}

void MB_FUNC_NAME(ifma_tomont52_nsm2_)(U64 r[], const U64 a[])
{
    MB_FUNC_NAME(ifma_amm52x5_)(r, a, (U64*)nsm2_rr_mb, (U64*)nsm2_mb, nsm2_k0_mb);
}

void MB_FUNC_NAME(ifma_frommont52_nsm2_)(U64 r[], const U64 a[])
{
    MB_FUNC_NAME(ifma_amm52_nsm2_)(r, a, (U64*)ones);
    MB_FUNC_NAME(ifma_fastred52_pnsm2_)(r, r);
}

/*
// computes r = 1/z = z^(nsm2-2) mod nsm2
//
// note: z in in Montgomery domain (as soon mul() and sqr() below are amm-functions
//       r in Montgomery domain too
*/
#define sqr_nsm2 MB_FUNC_NAME(ifma_ams52_nsm2_)
#define mul_nsm2 MB_FUNC_NAME(ifma_amm52_nsm2_)

void MB_FUNC_NAME(ifma_aminv52_nsm2_)(U64 r[], const U64 z[])
{
    int i;

    // pwr_z_Tbl[i][] = z^i, i=0,..,15
    __ALIGN64 U64 pwr_z_Tbl[16][LEN52];

    MB_FUNC_NAME(ifma_tomont52_nsm2_)(pwr_z_Tbl[0], (U64*)ones);
    MB_FUNC_NAME(mov_FESM2_)(pwr_z_Tbl[1], z);

    for (i = 2; i < 16; i += 2) {
        sqr_nsm2(pwr_z_Tbl[i], pwr_z_Tbl[i / 2]);
        mul_nsm2(pwr_z_Tbl[i + 1], pwr_z_Tbl[i], z);
    }

    // pwr = (nsm2-2) in big endian
    int8u pwr[] = "\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF"
                  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                  "\x72\x03\xDF\x6B\x21\xC6\x05\x2B"
                  "\x53\xBB\xF4\x09\x39\xD5\x41\x21";
    // init r = 1
    MB_FUNC_NAME(mov_FESM2_)(r, pwr_z_Tbl[0]);

    for (i = 0; i < 32; i++) {
        int v  = pwr[i];
        int hi = (v >> 4) & 0xF;
        int lo = v & 0xF;

        sqr_nsm2(r, r);
        sqr_nsm2(r, r);
        sqr_nsm2(r, r);
        sqr_nsm2(r, r);
        if (hi)
            mul_nsm2(r, r, pwr_z_Tbl[hi]);
        sqr_nsm2(r, r);
        sqr_nsm2(r, r);
        sqr_nsm2(r, r);
        sqr_nsm2(r, r);
        if (lo)
            mul_nsm2(r, r, pwr_z_Tbl[lo]);
    }
}

/*=====================================================================

 Specialized single operations in nsm2 - add, sub & neg

=====================================================================*/

void MB_FUNC_NAME(ifma_add52_nsm2_)(U64 r[], const U64 a[], const U64 b[])
{
    MB_FUNC_NAME(ifma_add52x5_)(r, a, b, (U64*)nsm2x2_mb);
}

void MB_FUNC_NAME(ifma_sub52_nsm2_)(U64 r[], const U64 a[], const U64 b[])
{
    MB_FUNC_NAME(ifma_sub52x5_)(r, a, b, (U64*)nsm2x2_mb);
}

void MB_FUNC_NAME(ifma_neg52_nsm2_)(U64 r[], const U64 a[])
{
    MB_FUNC_NAME(ifma_neg52x5_)(r, a, (U64*)nsm2x2_mb);
}

static __mb_mask MB_FUNC_NAME(lt_mbx_digit_)(const U64 a, const U64 b, const __mb_mask lt_mask)
{
    U64 d = mask_sub64(sub64(a, b), lt_mask, sub64(a, b), set1(1));
    return cmp64_mask(d, get_zero64(), _MM_CMPINT_LT);
}

/* r = (a>=nsm2)? a-nsm2 : a */
void MB_FUNC_NAME(ifma_fastred52_pnsm2_)(U64 R[], const U64 A[])
{
    /* r = a - b */
    U64 r0 = sub64(A[0], ((U64*)(nsm2_mb))[0]);
    U64 r1 = sub64(A[1], ((U64*)(nsm2_mb))[1]);
    U64 r2 = sub64(A[2], ((U64*)(nsm2_mb))[2]);
    U64 r3 = sub64(A[3], ((U64*)(nsm2_mb))[3]);
    U64 r4 = sub64(A[4], ((U64*)(nsm2_mb))[4]);

    /* lt = {r0 - r4} < 0 */
    __mb_mask lt = MB_FUNC_NAME(lt_mbx_digit_)(r0, get_zero64(), 0);
    lt           = MB_FUNC_NAME(lt_mbx_digit_)(r1, get_zero64(), lt);
    lt           = MB_FUNC_NAME(lt_mbx_digit_)(r2, get_zero64(), lt);
    lt           = MB_FUNC_NAME(lt_mbx_digit_)(r3, get_zero64(), lt);
    lt           = MB_FUNC_NAME(lt_mbx_digit_)(r4, get_zero64(), lt);

    r0 = mask_mov64(A[0], ~lt, r0);
    r1 = mask_mov64(A[1], ~lt, r1);
    r2 = mask_mov64(A[2], ~lt, r2);
    r3 = mask_mov64(A[3], ~lt, r3);
    r4 = mask_mov64(A[4], ~lt, r4);

    /* normalize r0 - r4 */
    NORM_ASHIFTR(r, 0, 1)
    NORM_ASHIFTR(r, 1, 2)
    NORM_ASHIFTR(r, 2, 3)
    NORM_ASHIFTR(r, 3, 4)

    R[0] = r0;
    R[1] = r1;
    R[2] = r2;
    R[3] = r3;
    R[4] = r4;
}

__mb_mask MB_FUNC_NAME(ifma_cmp_lt_nsm2_)(const U64 a[])
{
    return MB_FUNC_NAME(cmp_lt_FESM2_)(a, (const U64(*))nsm2_mb);
}

__mb_mask MB_FUNC_NAME(ifma_check_range_nsm2_)(const U64 A[])
{
    __mb_mask mask = MB_FUNC_NAME(is_zero_FESM2_)(A);
    mask |= ~MB_FUNC_NAME(ifma_cmp_lt_nsm2_)(A);

    return mask;
}

#endif /* #if (_MBX>=_MBX_K1) */
