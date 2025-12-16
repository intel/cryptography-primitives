/*************************************************************************
* Copyright (C) 2002 Intel Corporation
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

#ifndef IFMA_ARITH_P256_H
#define IFMA_ARITH_P256_H

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_math.h>
#if ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)
#include <crypto_mb/status.h>
#endif


#if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED))

/* Underlying prime's size */
#define P256_BITSIZE (256)

/* Lengths of FF elements */
#define P256_LEN52 NUMBER_OF_DIGITS(P256_BITSIZE, DIGIT_SIZE)
#define P256_LEN64 NUMBER_OF_DIGITS(P256_BITSIZE, 64)

__ALIGN64 static const int64u ones[P256_LEN52][sizeof(U64) / sizeof(int64u)] = {
    { REP_NUM_BUFF_DECL(1) },
    { REP_NUM_BUFF_DECL(0) },
    { REP_NUM_BUFF_DECL(0) },
    { REP_NUM_BUFF_DECL(0) },
    { REP_NUM_BUFF_DECL(0) }
};
static const int64u VMASK52[sizeof(U64) / sizeof(int64u)] = { REP_NUM_BUFF_DECL(DIGIT_MASK) };

#define NORM_LSHIFTR(R, I, J)                     \
    R##J = add64(R##J, srli64(R##I, DIGIT_SIZE)); \
    R##I = and64(R##I, loadu64(VMASK52));

#define NORM_ASHIFTR(R, I, J)                     \
    R##J = add64(R##J, srai64(R##I, DIGIT_SIZE)); \
    R##I = and64(R##I, loadu64(VMASK52));

__MBX_INLINE U64 cmov_U64(U64 a, U64 b, __mb_mask kmask) { return mask_mov64(a, kmask, b); }


/**********************************************************/
/* Internal functions that operates on field elements(FE) */
/**********************************************************/

/* Set FE to zero */
__MBX_INLINE void MB_FUNC_NAME(zero_FE256_)(U64 T[])
{
    T[0] = T[1] = T[2] = T[3] = T[4] = get_zero64();
}

/* Check if FE is zero */
__MBX_INLINE __mb_mask MB_FUNC_NAME(is_zero_FE256_)(const U64 T[])
{
    /* clang-format off */
    U64 Z = or64(or64(T[0], T[1]),
                 or64(or64(T[2], T[3]),
                      T[4])
                );
    /* clang-format on */

    return cmpeq64_mask(Z, get_zero64());
}

/* Move field element */
__MBX_INLINE void MB_FUNC_NAME(mov_FE256_)(U64 r[], const U64 a[])
{
    r[0] = a[0];
    r[1] = a[1];
    r[2] = a[2];
    r[3] = a[3];
    r[4] = a[4];
}

/* Move coordinate using mask: R = k? A : B */
OPTIMIZE_OFF_VS19
__MBX_INLINE void MB_FUNC_NAME(mask_mov_FE256_)(U64 R[], const U64 B[], __mb_mask k, const U64 A[])
{
    R[0] = mask_mov64(B[0], k, A[0]);
    R[1] = mask_mov64(B[1], k, A[1]);
    R[2] = mask_mov64(B[2], k, A[2]);
    R[3] = mask_mov64(B[3], k, A[3]);
    R[4] = mask_mov64(B[4], k, A[4]);
}

__MBX_INLINE void MB_FUNC_NAME(secure_mask_mov_FE256_)(U64 R[], U64 B[], __mb_mask k, const U64 A[])
{
    R[0] = select64(k, B[0], (U64*)(&A[0]));
    R[1] = select64(k, B[1], (U64*)(&A[1]));
    R[2] = select64(k, B[2], (U64*)(&A[2]));
    R[3] = select64(k, B[3], (U64*)(&A[3]));
    R[4] = select64(k, B[4], (U64*)(&A[4]));
}

/* Compare two FE */
__MBX_INLINE __mb_mask MB_FUNC_NAME(cmp_lt_FE256_)(const U64 A[], const U64 B[])
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
    return cmplt64_mask(r4, get_zero64());
}

/* Check two FE's equality */
__MBX_INLINE __mb_mask MB_FUNC_NAME(cmp_eq_FE256_)(const U64 A[], const U64 B[])
{
    __ALIGN64 U64 msg[P256_LEN52];

    msg[0] = xor64(A[0], B[0]);
    msg[1] = xor64(A[1], B[1]);
    msg[2] = xor64(A[2], B[2]);
    msg[3] = xor64(A[3], B[3]);
    msg[4] = xor64(A[4], B[4]);

    return MB_FUNC_NAME(is_zero_FE256_)(msg);
}

/**********************************************************/
/*     Declarations of p256 internal math kernels         */
/**********************************************************/

/* General 256-bit operations */
EXTERN_C void MB_FUNC_NAME(ifma_amm52x5_)(U64 R[],
                                          const U64 inpA[],
                                          const U64 inpB[],
                                          const U64 inpM[],
                                          const int64u* k0_mb);
EXTERN_C void MB_FUNC_NAME(ifma_ams52x5_)(U64 r[],
                                          const U64 a[],
                                          const U64 m[],
                                          const int64u* k0_mb);
EXTERN_C void MB_FUNC_NAME(ifma_add52x5_)(U64 R[], const U64 A[], const U64 B[], const U64 M[]);
EXTERN_C void MB_FUNC_NAME(ifma_sub52x5_)(U64 R[], const U64 A[], const U64 B[], const U64 M[]);
EXTERN_C void MB_FUNC_NAME(ifma_neg52x5_)(U64 R[], const U64 A[], const U64 M[]);

/* Specialized operations over NIST P256 */
EXTERN_C void MB_FUNC_NAME(ifma_tomont52_p256_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_frommont52_p256_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_ams52_p256_)(U64 r[], const U64 va[]);
EXTERN_C void MB_FUNC_NAME(ifma_amm52_p256_)(U64 r[], const U64 va[], const U64 vb[]);
EXTERN_C void MB_FUNC_NAME(ifma_aminv52_p256_)(U64 r[], const U64 z[]);
EXTERN_C void MB_FUNC_NAME(ifma_add52_p256_)(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void MB_FUNC_NAME(ifma_sub52_p256_)(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void MB_FUNC_NAME(ifma_neg52_p256_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_double52_p256_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_tripple52_p256_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_half52_p256_)(U64 r[], const U64 a[]);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_cmp_lt_p256_)(const U64 a[]);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_check_range_p256_)(const U64 a[]);


/* Specialized operations over EC NIST-P256 order */
EXTERN_C void MB_FUNC_NAME(ifma_tomont52_n256_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_frommont52_n256_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_ams52_n256_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_amm52_n256_)(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void MB_FUNC_NAME(ifma_aminv52_n256_)(U64 r[], const U64 a[]);
EXTERN_C void MB_FUNC_NAME(ifma_add52_n256_)(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void MB_FUNC_NAME(ifma_fastred52_pn256_)(U64 r[], const U64 a[]);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_cmp_lt_n256_)(const U64 a[]);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_check_range_n256_)(const U64 a[]);


#if (_MBX >= _MBX_K1)

/*
 * Internal AVX512 functions(_mb8), not used for AVX-IFMA
 */

/* Specialized operations over NIST P256 */
EXTERN_C void ifma_ams52_p256_dual_mb8(U64 r0[], U64 r1[], const U64 inp0[], const U64 inp1[]);
EXTERN_C void ifma_amm52_p256_dual_mb8(U64 r0[],
                                       U64 r1[],
                                       const U64 inp0A[],
                                       const U64 inp0B[],
                                       const U64 inp1A[],
                                       const U64 inp1B[]);

/* Specialized operations over EC NIST-P256 order */
EXTERN_C U64* ifma_n256_mb8(void);
EXTERN_C void ifma_sub52_n256_mb8(U64 r[], const U64 a[], const U64 b[]);
EXTERN_C void ifma_neg52_n256_mb8(U64 r[], const U64 a[]);

#elif ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)

/*
// Sets mbx_status based on the U64 value and already set prev_status:
//      an i-th bit is set in the mbx_status if (input[i+63:i] == 0xFFFFFFFFFFFFFFFF) & prev_status
//
// An internal AVX-IFMA version of MBX_SET_STS_BY_MASK, requiring U64 support.
*/
__MBX_INLINE mbx_status MBX_SET_STS_BY_U64(mbx_status prev_status, U64 input, mbx_status set_status)
{
    int64u input_parts[MB_WIDTH];
    // Extract 64-bit parts
    input_parts[0] = (int64u)_mm256_extract_epi64(input, 0);
    input_parts[1] = (int64u)_mm256_extract_epi64(input, 1);
    input_parts[2] = (int64u)_mm256_extract_epi64(input, 2);
    input_parts[3] = (int64u)_mm256_extract_epi64(input, 3);

    int numb;
    for (numb = 0; numb < MB_WIDTH; numb++) {
        prev_status |= ((mbx_status)input_parts[numb] & (set_status << numb * MB_WIDTH));
    }

    return prev_status;
}

#endif /* #if (_MBX >= _MBX_K1) */
#endif /* #if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)) */

#endif /* IFMA_ARITH_P256_H */
