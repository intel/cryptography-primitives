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

#ifndef IFMA_ECPOINT_P256_H
#define IFMA_ECPOINT_P256_H

#include "crypto_mb/status.h"
#include <internal/ecnist/ifma_arith_p256.h>

#if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED))

#ifndef BN_OPENSSL_DISABLE
#include <openssl/bn.h>
#include <openssl/ec.h>

#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/ecdsa.h>
#endif /* OPENSSL_IS_BORINGSSL */

#endif /* BN_OPENSSL_DISABLE */

typedef struct {
    U64 X[P256_LEN52];
    U64 Y[P256_LEN52];
    U64 Z[P256_LEN52];
} P256_POINT;

typedef struct {
    U64 x[P256_LEN52];
    U64 y[P256_LEN52];
} P256_POINT_AFFINE;

typedef struct {
    int64u x[P256_LEN52];
    int64u y[P256_LEN52];
} SINGLE_P256_POINT_AFFINE;


/* check if coordinate is zero */
__MBX_INLINE __mb_mask MB_FUNC_NAME(is_zero_point_cordinate_)(const U64 T[])
{
    return MB_FUNC_NAME(is_zero_FE256_)(T);
}

/* set point to infinity */
__MBX_INLINE void MB_FUNC_NAME(set_point_to_infinity_)(P256_POINT* r)
{
    r->X[0] = r->X[1] = r->X[2] = r->X[3] = r->X[4] = get_zero64();
    r->Y[0] = r->Y[1] = r->Y[2] = r->Y[3] = r->Y[4] = get_zero64();
    r->Z[0] = r->Z[1] = r->Z[2] = r->Z[3] = r->Z[4] = get_zero64();
}

/* set point to infinity by mask */
__MBX_INLINE void MB_FUNC_NAME(mask_set_point_to_infinity_)(P256_POINT* r, __mb_mask mask)
{
    U64 zeros = get_zero64();

    r->X[0] = mask_mov64(r->X[0], mask, zeros);
    r->X[1] = mask_mov64(r->X[1], mask, zeros);
    r->X[2] = mask_mov64(r->X[2], mask, zeros);
    r->X[3] = mask_mov64(r->X[3], mask, zeros);
    r->X[4] = mask_mov64(r->X[4], mask, zeros);

    r->Y[0] = mask_mov64(r->Y[0], mask, zeros);
    r->Y[1] = mask_mov64(r->Y[1], mask, zeros);
    r->Y[2] = mask_mov64(r->Y[2], mask, zeros);
    r->Y[3] = mask_mov64(r->Y[3], mask, zeros);
    r->Y[4] = mask_mov64(r->Y[4], mask, zeros);

    r->Z[0] = mask_mov64(r->Z[0], mask, zeros);
    r->Z[1] = mask_mov64(r->Z[1], mask, zeros);
    r->Z[2] = mask_mov64(r->Z[2], mask, zeros);
    r->Z[3] = mask_mov64(r->Z[3], mask, zeros);
    r->Z[4] = mask_mov64(r->Z[4], mask, zeros);
}

EXTERN_C void MB_FUNC_NAME(ifma_ec_nistp256_mul_pointbase_)(P256_POINT* r, const U64* scalar);
EXTERN_C void MB_FUNC_NAME(ifma_ec_nistp256_add_point_affine_)(P256_POINT* r,
                                                               const P256_POINT* p,
                                                               const P256_POINT_AFFINE* q);
EXTERN_C void MB_FUNC_NAME(ifma_ec_nistp256_add_point_)(P256_POINT* r,
                                                        const P256_POINT* p,
                                                        const P256_POINT* q);
EXTERN_C void MB_FUNC_NAME(ifma_ec_nistp256_mul_point_)(P256_POINT* r,
                                                        const P256_POINT* p,
                                                        const U64* scalar);
EXTERN_C void MB_FUNC_NAME(get_nistp256_ec_affine_coords_)(U64 x[], U64 y[], const P256_POINT* P);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_is_on_curve_p256_)(const P256_POINT* p, int use_jproj_coords);

/* 
 *   "Level 2" processing functions declaration
 */
mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_setup_)(
    int64u* pa_inv_eph_skey[MB_WIDTH],
    int64u* pa_sign_rp[MB_WIDTH],
    const int64u* const pa_eph_skey[MB_WIDTH],
    int8u* pBuffer);

mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_complete_)(
    int8u* pa_sign_r[MB_WIDTH],
    int8u* pa_sign_s[MB_WIDTH],
    const int8u* const pa_msg[MB_WIDTH],
    const int64u* const pa_sign_rp[MB_WIDTH],
    const int64u* const pa_inv_eph_skey[MB_WIDTH],
    const int64u* const pa_reg_skey[MB_WIDTH],
    int8u* pBuffer);

mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_)(int8u* pa_sign_r[MB_WIDTH],
                                                       int8u* pa_sign_s[MB_WIDTH],
                                                       const int8u* const pa_msg[MB_WIDTH],
                                                       const int64u* const pa_eph_skey[MB_WIDTH],
                                                       const int64u* const pa_reg_skey[MB_WIDTH],
                                                       int8u* pBuffer);

mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_verify_)(const int8u* const pa_sign_r[MB_WIDTH],
                                                         const int8u* const pa_sign_s[MB_WIDTH],
                                                         const int8u* const pa_msg[MB_WIDTH],
                                                         const int64u* const pa_pubx[MB_WIDTH],
                                                         const int64u* const pa_puby[MB_WIDTH],
                                                         const int64u* const pa_pubz[MB_WIDTH],
                                                         int8u* pBuffer,
                                                         int use_jproj_coords);

mbx_status MB_FUNC_NAME(internal_nistp256_ecdh_)(int8u* pa_shared_key[MB_WIDTH],
                                                 const int64u* const pa_skey[MB_WIDTH],
                                                 const int64u* const pa_pubx[MB_WIDTH],
                                                 const int64u* const pa_puby[MB_WIDTH],
                                                 const int64u* const pa_pubz[MB_WIDTH],
                                                 int8u* pBuffer,
                                                 int use_jproj_coords);

mbx_status MB_FUNC_NAME(internal_nistp256_ecpublic_key_)(int64u* pa_pubx[MB_WIDTH],
                                                         int64u* pa_puby[MB_WIDTH],
                                                         int64u* pa_pubz[MB_WIDTH],
                                                         const int64u* const pa_skey[MB_WIDTH],
                                                         int8u* pBuffer,
                                                         int use_jproj_coords);

/* 
 *   "Level 2" processing functions declaration, ssl-specific API
 */

#ifndef BN_OPENSSL_DISABLE

mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_setup_ssl_)(
    BIGNUM* pa_inv_skey[MB_WIDTH],
    BIGNUM* pa_sign_rp[MB_WIDTH],
    const BIGNUM* const pa_eph_skey[MB_WIDTH],
    int8u* pBuffer);

mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_complete_ssl_)(
    int8u* pa_sign_r[MB_WIDTH],
    int8u* pa_sign_s[MB_WIDTH],
    const int8u* const pa_msg[MB_WIDTH],
    const BIGNUM* const pa_sign_rp[MB_WIDTH],
    const BIGNUM* const pa_inv_eph_skey[MB_WIDTH],
    const BIGNUM* const pa_reg_skey[MB_WIDTH],
    int8u* pBuffer);

mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_ssl_)(
    int8u* pa_sign_r[MB_WIDTH],
    int8u* pa_sign_s[MB_WIDTH],
    const int8u* const pa_msg[MB_WIDTH],
    const BIGNUM* const pa_eph_skey[MB_WIDTH],
    const BIGNUM* const pa_reg_skey[MB_WIDTH],
    int8u* pBuffer);

mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_verify_ssl_)(
    const ECDSA_SIG* const pa_sig[MB_WIDTH],
    const int8u* const pa_msg[MB_WIDTH],
    const BIGNUM* const pa_pubx[MB_WIDTH],
    const BIGNUM* const pa_puby[MB_WIDTH],
    const BIGNUM* const pa_pubz[MB_WIDTH],
    int8u* pBuffer,
    int use_jproj_coords);


mbx_status MB_FUNC_NAME(internal_mbx_nistp256_ecdh_ssl_)(int8u* pa_shared_key[MB_WIDTH],
                                                         const BIGNUM* const pa_skey[MB_WIDTH],
                                                         const BIGNUM* const pa_pubx[MB_WIDTH],
                                                         const BIGNUM* const pa_puby[MB_WIDTH],
                                                         const BIGNUM* const pa_pubz[MB_WIDTH],
                                                         int8u* pBuffer,
                                                         int use_jproj_coords);

mbx_status MB_FUNC_NAME(internal_nistp256_ecpublic_key_ssl_)(BIGNUM* pa_pubx[MB_WIDTH],
                                                             BIGNUM* pa_puby[MB_WIDTH],
                                                             BIGNUM* pa_pubz[MB_WIDTH],
                                                             const BIGNUM* const pa_skey[MB_WIDTH],
                                                             int8u* pBuffer,
                                                             int use_jproj_coords);
#endif /* BN_OPENSSL_DISABLE */

#if (_MBX >= _MBX_K1)

/* set affine point to infinity */
__MBX_INLINE void set_point_affine_to_infinity_mb8(P256_POINT_AFFINE* r)
{
    r->x[0] = r->x[1] = r->x[2] = r->x[3] = r->x[4] = get_zero64();
    r->y[0] = r->y[1] = r->y[2] = r->y[3] = r->y[4] = get_zero64();
}

EXTERN_C void ifma_ec_nistp256_dbl_point_mb8(P256_POINT* r, const P256_POINT* p);
EXTERN_C const U64* ifma_ec_nistp256_coord_one_mb8(void);

#endif /* #if (_MBX >= _MBX_K1) */

#endif /* #if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)) */
#endif /* IFMA_ECPOINT_P256_H */
