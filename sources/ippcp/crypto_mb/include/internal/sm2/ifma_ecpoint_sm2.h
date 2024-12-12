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

#ifndef IFMA_ECPOINT_SM2_H
#define IFMA_ECPOINT_SM2_H

#include <crypto_mb/status.h>
#include <internal/sm2/ifma_arith_sm2.h>

#ifndef BN_OPENSSL_DISABLE
#include <openssl/bn.h>
#include <openssl/ec.h>
#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/ecdsa.h>
#endif
#endif /* BN_OPENSSL_DISABLE */

#if (_MBX >= _MBX_K1)

typedef struct {
    U64 X[PSM2_LEN52];
    U64 Y[PSM2_LEN52];
    U64 Z[PSM2_LEN52];
} SM2_POINT;

typedef struct {
    U64 x[PSM2_LEN52];
    U64 y[PSM2_LEN52];
} SM2_POINT_AFFINE;

typedef struct {
    int64u x[PSM2_LEN52];
    int64u y[PSM2_LEN52];
} SINGLE_SM2_POINT_AFFINE;

/* check if coordinate is zero */
__MBX_INLINE __mb_mask MB_FUNC_NAME(is_zero_point_cordinate_)(const U64 T[])
{
    return MB_FUNC_NAME(is_zero_FESM2_)(T);
}

/* set point to infinity */
__MBX_INLINE void MB_FUNC_NAME(set_point_to_infinity_)(SM2_POINT* r)
{
    r->X[0] = r->X[1] = r->X[2] = r->X[3] = r->X[4] = get_zero64();
    r->Y[0] = r->Y[1] = r->Y[2] = r->Y[3] = r->Y[4] = get_zero64();
    r->Z[0] = r->Z[1] = r->Z[2] = r->Z[3] = r->Z[4] = get_zero64();
}

/* set point to infinity by mask */
__MBX_INLINE void MB_FUNC_NAME(mask_set_point_to_infinity_)(SM2_POINT* r, __mb_mask mask)
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

/* set affine point to infinity */
__MBX_INLINE void MB_FUNC_NAME(set_point_affine_to_infinity_)(SM2_POINT_AFFINE* r)
{
    r->x[0] = r->x[1] = r->x[2] = r->x[3] = r->x[4] = get_zero64();
    r->y[0] = r->y[1] = r->y[2] = r->y[3] = r->y[4] = get_zero64();
}

EXTERN_C void MB_FUNC_NAME(ifma_ec_sm2_dbl_point_)(SM2_POINT* r, const SM2_POINT* p);
EXTERN_C void MB_FUNC_NAME(ifma_ec_sm2_add_point_)(SM2_POINT* r,
                                                   const SM2_POINT* p,
                                                   const SM2_POINT* q);
EXTERN_C void MB_FUNC_NAME(ifma_ec_sm2_add_point_affine_)(SM2_POINT* r,
                                                          const SM2_POINT* p,
                                                          const SM2_POINT_AFFINE* q);
EXTERN_C void MB_FUNC_NAME(ifma_ec_sm2_mul_point_)(SM2_POINT* r,
                                                   const SM2_POINT* p,
                                                   const U64* scalar);
EXTERN_C void MB_FUNC_NAME(ifma_ec_sm2_mul_pointbase_)(SM2_POINT* r, const U64* scalar);
EXTERN_C void MB_FUNC_NAME(get_sm2_ec_affine_coords_)(U64 x[], U64 y[], const SM2_POINT* P);
EXTERN_C const U64* MB_FUNC_NAME(ifma_ec_sm2_coord_one_)(void);
EXTERN_C __mb_mask MB_FUNC_NAME(ifma_is_on_curve_psm2_)(const SM2_POINT* p, int use_jproj_coords);


#ifndef BN_OPENSSL_DISABLE

mbx_status internal_avx512_sm2_ecdh_ssl_mb8(int8u* pa_shared_key[8],
                                            const BIGNUM* const pa_skey[8],
                                            const BIGNUM* const pa_pubx[8],
                                            const BIGNUM* const pa_puby[8],
                                            const BIGNUM* const pa_pubz[8],
                                            int8u* pBuffer,
                                            int use_jproj_coords);

mbx_status internal_avx512_sm2_ecdsa_sign_ssl_mb8(int8u* pa_sign_r[8],
                                                  int8u* pa_sign_s[8],
                                                  const int8u* const pa_user_id[8],
                                                  const int user_id_len[8],
                                                  const int8u* const pa_msg[8],
                                                  const int msg_len[8],
                                                  const BIGNUM* const pa_eph_skey[8],
                                                  const BIGNUM* const pa_reg_skey[8],
                                                  const BIGNUM* const pa_pubx[8],
                                                  const BIGNUM* const pa_puby[8],
                                                  const BIGNUM* const pa_pubz[8],
                                                  int8u* pBuffer,
                                                  int use_jproj_coords,
                                                  int* user_id_len_checked);

mbx_status internal_avx512_sm2_ecdsa_verify_ssl_mb8(const ECDSA_SIG* const pa_sig[8],
                                                    const int8u* const pa_user_id[8],
                                                    const int user_id_len[8],
                                                    const int8u* const pa_msg[8],
                                                    const int msg_len[8],
                                                    const BIGNUM* const pa_pubx[8],
                                                    const BIGNUM* const pa_puby[8],
                                                    const BIGNUM* const pa_pubz[8],
                                                    int8u* pBuffer,
                                                    int use_jproj_coords,
                                                    int* user_id_len_checked);

mbx_status internal_avx512_sm2_ecpublic_key_ssl_mb8(BIGNUM* pa_pubx[8],
                                                    BIGNUM* pa_puby[8],
                                                    BIGNUM* pa_pubz[8],
                                                    const BIGNUM* const pa_skey[8],
                                                    int8u* pBuffer,
                                                    int use_jproj_coords);

#endif /* BN_OPENSSL_DISABLE */

mbx_status internal_avx512_sm2_ecdh_mb8(int8u* pa_shared_key[8],
                                        const int64u* const pa_skey[8],
                                        const int64u* const pa_pubx[8],
                                        const int64u* const pa_puby[8],
                                        const int64u* const pa_pubz[8],
                                        int8u* pBuffer,
                                        int use_jproj_coords);

mbx_status internal_avx512_sm2_ecdsa_sign_mb8(int8u* pa_sign_r[8],
                                              int8u* pa_sign_s[8],
                                              const int8u* const pa_user_id[8],
                                              const int user_id_len[8],
                                              const int8u* const pa_msg[8],
                                              const int msg_len[8],
                                              const int64u* const pa_eph_skey[8],
                                              const int64u* const pa_reg_skey[8],
                                              const int64u* const pa_pubx[8],
                                              const int64u* const pa_puby[8],
                                              const int64u* const pa_pubz[8],
                                              int8u* pBuffer,
                                              int use_jproj_coords,
                                              int* user_id_len_checked);

mbx_status internal_avx512_sm2_ecdsa_verify_mb8(const int8u* const pa_sign_r[8],
                                                const int8u* const pa_sign_s[8],
                                                const int8u* const pa_user_id[8],
                                                const int user_id_len[8],
                                                const int8u* const pa_msg[8],
                                                const int msg_len[8],
                                                const int64u* const pa_pubx[8],
                                                const int64u* const pa_puby[8],
                                                const int64u* const pa_pubz[8],
                                                int8u* pBuffer,
                                                int use_jproj_coords,
                                                int* user_id_len_checked);

mbx_status internal_avx512_sm2_ecpublic_key_mb8(int64u* pa_pubx[8],
                                                int64u* pa_puby[8],
                                                int64u* pa_pubz[8],
                                                const int64u* const pa_skey[8],
                                                int8u* pBuffer,
                                                int use_jproj_coords);

#endif /* #if (_MBX>=_MBX_K1) */

#endif /* IFMA_ECPOINT_PSM2_H */
