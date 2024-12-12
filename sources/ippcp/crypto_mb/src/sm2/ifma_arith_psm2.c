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

/*
// prime256 = 2^256 - 2^224 - 2^96 + 2^64 - 1
// in 2^52 radix
*/
__ALIGN64 static const int64u psm2_mb[PSM2_LEN52][8] = { { REP8_DECL(0xfffffffffffff) },
                                                         { REP8_DECL(0xff00000000fff) },
                                                         { REP8_DECL(0xfffffffffffff) },
                                                         { REP8_DECL(0xfffffffffffff) },
                                                         { REP8_DECL(0x0fffffffeffff) } };

__ALIGN64 static const int64u psm2x2_mb[PSM2_LEN52][8] = { { REP8_DECL(0xffffffffffffe) },
                                                           { REP8_DECL(0xfe00000001fff) },
                                                           { REP8_DECL(0xfffffffffffff) },
                                                           { REP8_DECL(0xfffffffffffff) },
                                                           { REP8_DECL(0x1fffffffdffff) } };

/* to Montgomery conversion constant
// rr = 2^((PSM2_LEN52*DIGIT_SIZE)*2) mod psm2
*/
__ALIGN64 static const int64u psm2_rr_mb[PSM2_LEN52][8] = { { REP8_DECL(0x0020000000300) },
                                                            { REP8_DECL(0xffffffff00000) },
                                                            { REP8_DECL(0x0000100000002) },
                                                            { REP8_DECL(0x0200000001000) },
                                                            { REP8_DECL(0x0000004000000) } };

/* other constants */
__ALIGN64 static const int64u VDIGIT_MASK_[8] = { DIGIT_MASK, DIGIT_MASK, DIGIT_MASK, DIGIT_MASK,
                                                  DIGIT_MASK, DIGIT_MASK, DIGIT_MASK, DIGIT_MASK };
#define VDIGIT_MASK loadu64(VDIGIT_MASK_)

#define ROUND_MUL(I, J, LO, HI)       \
    (LO) = fma52lo(LO, va[I], vb[J]); \
    (HI) = fma52hi(HI, va[I], vb[J])


//TODO: reduction
#define MUL_ADD_PSM2(u, res0, res1, res2, res3, res4, res5)                        \
    {                                                                              \
        /* a * ( 2^52 - 1 ) = 2^52 * a - a */                                      \
        U64 u = and64(res0, VDIGIT_MASK);                                          \
        /* res0 = sub64(res0, u); */                    /* Zero out low 52 bits */ \
        (res1) = add64(res1, srli64(res0, DIGIT_SIZE)); /* Carry propagation */    \
        (res1) = add64(res1, u);                                                   \
        (res1) = fma52lo(res1, u, ((U64*)psm2_mb)[1]);                             \
        (res2) = fma52hi(res2, u, ((U64*)psm2_mb)[1]);                             \
        (res2) = sub64(res2, u);                                                   \
        (res4) = add64(res4, u);                                                   \
        (res4) = fma52lo(res4, u, ((U64*)psm2_mb)[4]);                             \
        (res5) = fma52hi(res5, u, ((U64*)psm2_mb)[4]);                             \
    }

void MB_FUNC_NAME(ifma_amm52_psm2_)(U64 r[], const U64 va[], const U64 vb[])
{
    U64 r0, r1, r2, r3, r4, r5, r6, r7, r8, r9;
    r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = r8 = r9 = get_zero64();

    // full multiplication
    ROUND_MUL(0, 0, r0, r1);
    ROUND_MUL(1, 0, r1, r2);
    ROUND_MUL(2, 0, r2, r3);
    ROUND_MUL(3, 0, r3, r4);
    ROUND_MUL(4, 0, r4, r5);

    ROUND_MUL(0, 1, r1, r2);
    ROUND_MUL(1, 1, r2, r3);
    ROUND_MUL(2, 1, r3, r4);
    ROUND_MUL(3, 1, r4, r5);
    ROUND_MUL(4, 1, r5, r6);

    ROUND_MUL(0, 2, r2, r3);
    ROUND_MUL(1, 2, r3, r4);
    ROUND_MUL(2, 2, r4, r5);
    ROUND_MUL(3, 2, r5, r6);
    ROUND_MUL(4, 2, r6, r7);

    ROUND_MUL(0, 3, r3, r4);
    ROUND_MUL(1, 3, r4, r5);
    ROUND_MUL(2, 3, r5, r6);
    ROUND_MUL(3, 3, r6, r7);
    ROUND_MUL(4, 3, r7, r8);

    ROUND_MUL(0, 4, r4, r5);
    ROUND_MUL(1, 4, r5, r6);
    ROUND_MUL(2, 4, r6, r7);
    ROUND_MUL(3, 4, r7, r8);
    ROUND_MUL(4, 4, r8, r9);

    //reduction
    MUL_ADD_PSM2(u0, r0, r1, r2, r3, r4, r5);
    MUL_ADD_PSM2(u1, r1, r2, r3, r4, r5, r6);
    MUL_ADD_PSM2(u2, r2, r3, r4, r5, r6, r7);
    MUL_ADD_PSM2(u3, r3, r4, r5, r6, r7, r8);
    MUL_ADD_PSM2(u4, r4, r5, r6, r7, r8, r9);

    NORM_LSHIFTR(r, 5, 6)
    NORM_LSHIFTR(r, 6, 7)
    NORM_LSHIFTR(r, 7, 8)
    NORM_LSHIFTR(r, 8, 9)

    r[0] = r5;
    r[1] = r6;
    r[2] = r7;
    r[3] = r8;
    r[4] = r9;
}

void MB_FUNC_NAME(ifma_ams52_psm2_)(U64 r[], const U64 va[])
{
    U64 r0, r1, r2, r3, r4, r5, r6, r7, r8, r9;
    r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = r8 = r9 = get_zero64();

    const U64* vb = va;

    ROUND_MUL(0, 1, r1, r2);
    ROUND_MUL(0, 2, r2, r3);
    ROUND_MUL(0, 3, r3, r4);
    ROUND_MUL(0, 4, r4, r5);
    ROUND_MUL(1, 4, r5, r6);
    ROUND_MUL(2, 4, r6, r7);
    ROUND_MUL(3, 4, r7, r8);

    ROUND_MUL(1, 2, r3, r4);
    ROUND_MUL(1, 3, r4, r5);

    ROUND_MUL(2, 3, r5, r6);

    r1 = add64(r1, r1);
    r2 = add64(r2, r2);
    r3 = add64(r3, r3);
    r4 = add64(r4, r4);
    r5 = add64(r5, r5);
    r6 = add64(r6, r6);
    r7 = add64(r7, r7);
    r8 = add64(r8, r8);

    ROUND_MUL(0, 0, r0, r1);
    ROUND_MUL(1, 1, r2, r3);
    ROUND_MUL(2, 2, r4, r5);
    ROUND_MUL(3, 3, r6, r7);
    ROUND_MUL(4, 4, r8, r9);

    //reduction
    MUL_ADD_PSM2(u0, r0, r1, r2, r3, r4, r5);
    MUL_ADD_PSM2(u1, r1, r2, r3, r4, r5, r6);
    MUL_ADD_PSM2(u2, r2, r3, r4, r5, r6, r7);
    MUL_ADD_PSM2(u3, r3, r4, r5, r6, r7, r8);
    MUL_ADD_PSM2(u4, r4, r5, r6, r7, r8, r9);

    NORM_LSHIFTR(r, 5, 6)
    NORM_LSHIFTR(r, 6, 7)
    NORM_LSHIFTR(r, 7, 8)
    NORM_LSHIFTR(r, 8, 9)

    r[0] = r5;
    r[1] = r6;
    r[2] = r7;
    r[3] = r8;
    r[4] = r9;
}

#define sqr_psm2 MB_FUNC_NAME(ifma_ams52_psm2_)
#define mul_psm2 MB_FUNC_NAME(ifma_amm52_psm2_)

#define sqr_psm2_x2(res, target) \
    {                            \
        sqr_psm2(res, target);   \
        sqr_psm2(res, res);      \
    }

#define sqr_psm2_x4(res, target)  \
    {                             \
        sqr_psm2_x2(res, target); \
        sqr_psm2_x2(res, res);    \
    }

#define sqr_psm2_x8(res, target)  \
    {                             \
        sqr_psm2_x4(res, target); \
        sqr_psm2_x4(res, res);    \
    }

#define sqr_psm2_x16(res, target) \
    {                             \
        sqr_psm2_x8(res, target); \
        sqr_psm2_x8(res, res);    \
    }

#define sqr_psm2_x32(res, target)  \
    {                              \
        sqr_psm2_x16(res, target); \
        sqr_psm2_x16(res, res);    \
    }

#define sqr_psm2_x64(res, target)  \
    {                              \
        sqr_psm2_x32(res, target); \
        sqr_psm2_x32(res, res);    \
    }

void MB_FUNC_NAME(ifma_aminv52_psm2_)(U64 r[], const U64 z[])
{
    __ALIGN64 U64 tmp1[PSM2_LEN52];
    __ALIGN64 U64 tmp2[PSM2_LEN52];

    __ALIGN64 U64 D[PSM2_LEN52];
    __ALIGN64 U64 E[PSM2_LEN52];
    __ALIGN64 U64 F[PSM2_LEN52];

    sqr_psm2(tmp1, z);
    mul_psm2(F, tmp1, z); /* F = z^3 */

    /* tmp2 = z^0xC */
    sqr_psm2_x2(tmp2, F);

    mul_psm2(D, tmp2, z);    /* D = z^0xD */
    mul_psm2(E, tmp2, tmp1); /* E = z^0xE */
    mul_psm2(F, tmp2, F);    /* F = z^0xF */

    /* tmp2 = z^0xF0 */
    sqr_psm2_x4(tmp2, F);

    mul_psm2(D, tmp2, D); /* D = z^0xFD */
    mul_psm2(E, tmp2, E); /* E = z^0xFE */
    mul_psm2(F, tmp2, F); /* F = z^0xFF */

    /* tmp2 = z^0xFF00 */
    sqr_psm2_x8(tmp2, F);

    mul_psm2(D, tmp2, D); /* D = z^0xFFFD */
    mul_psm2(E, tmp2, E); /* E = z^0xFFFE */
    mul_psm2(F, tmp2, F); /* F = z^0xFFFF */

    /* tmp2 = z^0xFFFF0000 */
    sqr_psm2_x16(tmp2, F);

    mul_psm2(D, tmp2, D); /* D = z^0xFFFFFFFD */
    mul_psm2(E, tmp2, E); /* E = z^0xFFFFFFFE */
    mul_psm2(F, tmp2, F); /* F = z^0xFFFFFFFF */

    /* z ^ FFFFFFFE 00000000 */
    sqr_psm2_x32(r, E);
    /* z ^ FFFFFFFE FFFFFFFF */
    mul_psm2(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF 00000000 */
    sqr_psm2_x32(r, r);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF */
    mul_psm2(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF 00000000 */
    sqr_psm2_x32(r, r);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF */
    mul_psm2(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 00000000 */
    sqr_psm2_x32(r, r);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF */
    mul_psm2(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 00000000 */
    sqr_psm2_x64(r, r);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF */
    mul_psm2(r, r, F);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF 00000000 */
    sqr_psm2_x32(r, r);
    /* z ^ FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFD */
    mul_psm2(r, r, D);
}

void MB_FUNC_NAME(ifma_reduce52_psm2_)(U64 R[], const U64 A[])
{
    /* r = a - p384_mb */
    U64 r0 = sub64(A[0], ((U64*)(psm2_mb))[0]);
    U64 r1 = sub64(A[1], ((U64*)(psm2_mb))[1]);
    U64 r2 = sub64(A[2], ((U64*)(psm2_mb))[2]);
    U64 r3 = sub64(A[3], ((U64*)(psm2_mb))[3]);
    U64 r4 = sub64(A[4], ((U64*)(psm2_mb))[4]);

    /* normalize r0 - r4 */
    NORM_ASHIFTR(r, 0, 1)
    NORM_ASHIFTR(r, 1, 2)
    NORM_ASHIFTR(r, 2, 3)
    NORM_ASHIFTR(r, 3, 4)

    /* r = a<psm2_mb? a : r */
    __mb_mask lt = cmp64_mask(r4, get_zero64(), _MM_CMPINT_LT);
    R[0]         = mask_mov64(r0, lt, A[0]);
    R[1]         = mask_mov64(r1, lt, A[1]);
    R[2]         = mask_mov64(r2, lt, A[2]);
    R[3]         = mask_mov64(r3, lt, A[3]);
    R[4]         = mask_mov64(r4, lt, A[4]);
}

void MB_FUNC_NAME(ifma_tomont52_psm2_)(U64 r[], const U64 a[])
{
    MB_FUNC_NAME(ifma_amm52_psm2_)(r, a, (U64*)psm2_rr_mb);
}

void MB_FUNC_NAME(ifma_frommont52_psm2_)(U64 r[], const U64 a[])
{
    MB_FUNC_NAME(ifma_amm52_psm2_)(r, a, (U64*)ones);
    MB_FUNC_NAME(ifma_reduce52_psm2_)(r, r);
}

void MB_FUNC_NAME(ifma_add52_psm2_)(U64 r[], const U64 a[], const U64 b[])
{
    /* r = a + b */
    U64 r0 = add64(a[0], b[0]);
    U64 r1 = add64(a[1], b[1]);
    U64 r2 = add64(a[2], b[2]);
    U64 r3 = add64(a[3], b[3]);
    U64 r4 = add64(a[4], b[4]);

    /* t = r - M */
    U64 t0 = sub64(r0, ((U64*)psm2x2_mb)[0]);
    U64 t1 = sub64(r1, ((U64*)psm2x2_mb)[1]);
    U64 t2 = sub64(r2, ((U64*)psm2x2_mb)[2]);
    U64 t3 = sub64(r3, ((U64*)psm2x2_mb)[3]);
    U64 t4 = sub64(r4, ((U64*)psm2x2_mb)[4]);

    /* normalize r0, r1, r2, r3, r4 */
    NORM_LSHIFTR(r, 0, 1)
    NORM_LSHIFTR(r, 1, 2)
    NORM_LSHIFTR(r, 2, 3)
    NORM_LSHIFTR(r, 3, 4)

    /* normalize t0, t1, t2, t3, t4 */
    NORM_ASHIFTR(t, 0, 1)
    NORM_ASHIFTR(t, 1, 2)
    NORM_ASHIFTR(t, 2, 3)
    NORM_ASHIFTR(t, 3, 4)

    /* condition mask t4<0? (-1) : 0 */
    __mb_mask cmask = cmp64_mask(t4, get_zero64(), _MM_CMPINT_LT);

    r[0] = cmov_U64(t0, r0, cmask);
    r[1] = cmov_U64(t1, r1, cmask);
    r[2] = cmov_U64(t2, r2, cmask);
    r[3] = cmov_U64(t3, r3, cmask);
    r[4] = cmov_U64(t4, r4, cmask);
}

void MB_FUNC_NAME(ifma_sub52_psm2_)(U64 r[], const U64 a[], const U64 b[])
{
    /* r = a-b */
    U64 r0 = sub64(a[0], b[0]);
    U64 r1 = sub64(a[1], b[1]);
    U64 r2 = sub64(a[2], b[2]);
    U64 r3 = sub64(a[3], b[3]);
    U64 r4 = sub64(a[4], b[4]);

    /* t = r + M */
    U64 t0 = add64(r0, ((U64*)psm2x2_mb)[0]);
    U64 t1 = add64(r1, ((U64*)psm2x2_mb)[1]);
    U64 t2 = add64(r2, ((U64*)psm2x2_mb)[2]);
    U64 t3 = add64(r3, ((U64*)psm2x2_mb)[3]);
    U64 t4 = add64(r4, ((U64*)psm2x2_mb)[4]);

    /* normalize r0, r1, r2, r3, r4 */
    NORM_ASHIFTR(r, 0, 1)
    NORM_ASHIFTR(r, 1, 2)
    NORM_ASHIFTR(r, 2, 3)
    NORM_ASHIFTR(r, 3, 4)

    /* normalize t0, t1, t2, t3, t4 */
    NORM_ASHIFTR(t, 0, 1)
    NORM_ASHIFTR(t, 1, 2)
    NORM_ASHIFTR(t, 2, 3)
    NORM_ASHIFTR(t, 3, 4)

    /* condition mask t4<0? (-1) : 0 */
    __mb_mask cmask = cmp64_mask(r4, get_zero64(), _MM_CMPINT_LT);

    r[0] = cmov_U64(r0, t0, cmask);
    r[1] = cmov_U64(r1, t1, cmask);
    r[2] = cmov_U64(r2, t2, cmask);
    r[3] = cmov_U64(r3, t3, cmask);
    r[4] = cmov_U64(r4, t4, cmask);
}

void MB_FUNC_NAME(ifma_neg52_psm2_)(U64 r[], const U64 a[])
{
    /*  mask = a[]!=0? 1 : 0 */
    U64 t          = _mm512_or_epi64(a[0], a[1]);
    t              = _mm512_or_epi64(t, a[2]);
    t              = _mm512_or_epi64(t, a[3]);
    t              = _mm512_or_epi64(t, a[4]);
    __mb_mask mask = cmp64_mask(t, get_zero64(), _MM_CMPINT_NE);

    /* r = M - A */
    U64 r0 = _mm512_maskz_sub_epi64(mask, ((U64*)psm2x2_mb)[0], a[0]);
    U64 r1 = _mm512_maskz_sub_epi64(mask, ((U64*)psm2x2_mb)[1], a[1]);
    U64 r2 = _mm512_maskz_sub_epi64(mask, ((U64*)psm2x2_mb)[2], a[2]);
    U64 r3 = _mm512_maskz_sub_epi64(mask, ((U64*)psm2x2_mb)[3], a[3]);
    U64 r4 = _mm512_maskz_sub_epi64(mask, ((U64*)psm2x2_mb)[4], a[4]);

    /* normalize r0, r1, r2, r3, r4 */
    NORM_ASHIFTR(r, 0, 1)
    NORM_ASHIFTR(r, 1, 2)
    NORM_ASHIFTR(r, 2, 3)
    NORM_ASHIFTR(r, 3, 4)

    r[0] = r0;
    r[1] = r1;
    r[2] = r2;
    r[3] = r3;
    r[4] = r4;
}

void MB_FUNC_NAME(ifma_double52_psm2_)(U64 r[], const U64 a[])
{
    MB_FUNC_NAME(ifma_add52_psm2_)(r, a, a);
}

void MB_FUNC_NAME(ifma_tripple52_psm2_)(U64 r[], const U64 a[])
{
    U64 t[PSM2_LEN52];
    MB_FUNC_NAME(ifma_add52_psm2_)(t, a, a);
    MB_FUNC_NAME(ifma_add52_psm2_)(r, t, a);
}

void MB_FUNC_NAME(ifma_half52_psm2_)(U64 r[], const U64 a[])
{
    U64 one  = set1(1);
    U64 base = set1(DIGIT_BASE);

    /* res = a + is_odd(a)? psm2 : 0 */
    U64 mask = sub64(get_zero64(), and64(a[0], one));
    U64 t0   = add64(a[0], and64(((U64*)psm2_mb)[0], mask));
    U64 t1   = add64(a[1], and64(((U64*)psm2_mb)[1], mask));
    U64 t2   = add64(a[2], and64(((U64*)psm2_mb)[2], mask));
    U64 t3   = add64(a[3], and64(((U64*)psm2_mb)[3], mask));
    U64 t4   = add64(a[4], and64(((U64*)psm2_mb)[4], mask));

    /* t =>> 1 */
    mask = sub64(get_zero64(), and64(t1, one));
    t0   = add64(t0, and64(base, mask));
    t0   = srli64(t0, 1);

    mask = sub64(get_zero64(), and64(t2, one));
    t1   = add64(t1, and64(base, mask));
    t1   = srli64(t1, 1);

    mask = sub64(get_zero64(), and64(t3, one));
    t2   = add64(t2, and64(base, mask));
    t2   = srli64(t2, 1);

    mask = sub64(get_zero64(), and64(t4, one));
    t3   = add64(t3, and64(base, mask));
    t3   = srli64(t3, 1);

    t4 = srli64(t4, 1);

    /* normalize t0, t1, t2, t3, t4 */
    NORM_LSHIFTR(t, 0, 1)
    NORM_LSHIFTR(t, 1, 2)
    NORM_LSHIFTR(t, 2, 3)
    NORM_LSHIFTR(t, 3, 4)

    r[0] = t0;
    r[1] = t1;
    r[2] = t2;
    r[3] = t3;
    r[4] = t4;
}

__mb_mask MB_FUNC_NAME(ifma_cmp_lt_psm2_)(const U64 a[])
{
    return MB_FUNC_NAME(cmp_lt_FESM2_)(a, (const U64(*))psm2_mb);
}

__mb_mask MB_FUNC_NAME(ifma_check_range_psm2_)(const U64 A[])
{
    __mb_mask mask = MB_FUNC_NAME(is_zero_FESM2_)(A);
    mask |= ~MB_FUNC_NAME(ifma_cmp_lt_psm2_)(A);

    return mask;
}

#endif /* #if (_MBX>=_MBX_K1) */
