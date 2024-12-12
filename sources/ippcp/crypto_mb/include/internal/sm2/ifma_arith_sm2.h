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

#ifndef IFMA_ARITH_SM2_H
#define IFMA_ARITH_SM2_H

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_math.h>
#include <internal/ecnist/ifma_arith_p256.h>

#if (_MBX >= _MBX_K1)

/* underlying prime's size */
#define PSM2_BITSIZE (256)

#define PSM2_LEN52 NUMBER_OF_DIGITS(PSM2_BITSIZE, DIGIT_SIZE)
#define PSM2_LEN64 NUMBER_OF_DIGITS(PSM2_BITSIZE, 64)
#define PSM2_LEN8  NUMBER_OF_DIGITS(PSM2_BITSIZE, 8)

/* set FE to zero */
__MBX_INLINE void MB_FUNC_NAME(zero_FESM2_)(U64 T[])
{
    T[0] = T[1] = T[2] = T[3] = T[4] = get_zero64();
}

/* check if FE is zero */
__MBX_INLINE __mb_mask MB_FUNC_NAME(is_zero_FESM2_)(const U64 T[])
{
    U64 Z = or64(or64(T[0], T[1]), or64(or64(T[2], T[3]), T[4]));
    return cmpeq64_mask(Z, get_zero64());
}

/* move field element */
__MBX_INLINE void MB_FUNC_NAME(mov_FESM2_)(U64 r[], const U64 a[])
{
    r[0] = a[0];
    r[1] = a[1];
    r[2] = a[2];
    r[3] = a[3];
    r[4] = a[4];
}

/* move coordinate using mask: R = k? A : B */
__MBX_INLINE void MB_FUNC_NAME(mask_mov_FESM2_)(U64 R[], const U64 B[], __mb_mask k, const U64 A[])
{
    R[0] = mask_mov64(B[0], k, A[0]);
    R[1] = mask_mov64(B[1], k, A[1]);
    R[2] = mask_mov64(B[2], k, A[2]);
    R[3] = mask_mov64(B[3], k, A[3]);
    R[4] = mask_mov64(B[4], k, A[4]);
}

__MBX_INLINE void MB_FUNC_NAME(secure_mask_mov_FESM2_)(U64 R[], U64 B[], __mb_mask k, const U64 A[])
{
    R[0] = select64(k, B[0], (U64*)(&A[0]));
    R[1] = select64(k, B[1], (U64*)(&A[1]));
    R[2] = select64(k, B[2], (U64*)(&A[2]));
    R[3] = select64(k, B[3], (U64*)(&A[3]));
    R[4] = select64(k, B[4], (U64*)(&A[4]));
}

/* compare two FE */
__MBX_INLINE __mb_mask MB_FUNC_NAME(cmp_lt_FESM2_)(const U64 A[], const U64 B[])
{
    /* r = a - b */
    U64 r0 = sub64(A[0], B[0]);
    U64 r1 = sub64(A[1], B[1]);
    U64 r2 = sub64(A[2], B[2]);
    U64 r3 = sub64(A[3], B[3]);
    U64 r4 = sub64(A[4], B[4]);

    /* normalize r0 – r4 */
    NORM_ASHIFTR(r, 0, 1)
    NORM_ASHIFTR(r, 1, 2)
    NORM_ASHIFTR(r, 2, 3)
    NORM_ASHIFTR(r, 3, 4)

    /* return mask LT */
    return cmp64_mask(r4, get_zero64(), _MM_CMPINT_LT);
}

__MBX_INLINE __mb_mask MB_FUNC_NAME(cmp_eq_FESM2_)(const U64 A[], const U64 B[])
{
    __ALIGN64 U64 msg[PSM2_LEN52];

    msg[0] = xor64(A[0], B[0]);
    msg[1] = xor64(A[1], B[1]);
    msg[2] = xor64(A[2], B[2]);
    msg[3] = xor64(A[3], B[3]);
    msg[4] = xor64(A[4], B[4]);

    return MB_FUNC_NAME(is_zero_FESM2_)(msg);
}

/* Specialized operations over EC SM2 prime */
EXTERN_C void MB_FUNC_NAME(ifma_tomont52_psm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_frommont52_psm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_amm52_psm2_)(U64 r[], const U64 va[], const U64 vb[]);
EXTERN_C void MB_FUNC_NAME(ifma_ams52_psm2_)(U64 r[], const U64 va[]);
EXTERN_C void MB_FUNC_NAME(ifma_aminv52_psm2_)(U64 r[], const U64 z[]);
EXTERN_C void MB_FUNC_NAME(ifma_add52_psm2_)(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void MB_FUNC_NAME(ifma_sub52_psm2_)(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void MB_FUNC_NAME(ifma_neg52_psm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_double52_psm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_tripple52_psm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_half52_psm2_)(U64 r[], const U64 a[]);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_cmp_lt_psm2_)(const U64 a[]);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_check_range_psm2_)(const U64 a[]);

/* Specialized operations over EC SM2 order */
EXTERN_C U64* MB_FUNC_NAME(ifma_nsm2_)(void);
EXTERN_C void MB_FUNC_NAME(ifma_tomont52_nsm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_frommont52_nsm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_ams52_nsm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_amm52_nsm2_)(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void MB_FUNC_NAME(ifma_aminv52_nsm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_add52_nsm2_)(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void MB_FUNC_NAME(ifma_sub52_nsm2_)(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void MB_FUNC_NAME(ifma_neg52_nsm2_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_fastred52_pnsm2_)(U64 r[], const U64 a[]);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_cmp_lt_nsm2_)(const U64 a[]);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_check_range_nsm2_)(const U64 a[]);

#endif /* #if (_MBX>=_MBX_K1) */

#endif /* IFMA_ARITH_SM2_H */
