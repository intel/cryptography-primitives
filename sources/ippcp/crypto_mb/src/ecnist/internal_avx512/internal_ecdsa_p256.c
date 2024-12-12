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
#include <internal/common/ifma_cvt52.h>
#include <internal/ecnist/ifma_ecpoint_p256.h>
#include <internal/rsa/ifma_rsa_arith.h>

#if (_MBX >= _MBX_K1)

/*
// common functions
*/

/*
// compute secret key inversion
//
// inv_skey 1/skey mod n256
//
// note: pay attention on skey[] representation
//       it should be FE element of N256 based GF
*/
static void nistp256_ecdsa_inv_keys_mb8(U64 inv_skey[], const U64 skey[], int8u pBuffer[])
{
    /* compute inversion over n256 of secret keys */
    MB_FUNC_NAME(ifma_tomont52_n256_)(inv_skey, skey);
    ifma_aminv52_n256_mb8(inv_skey, inv_skey); /* 1/skeys mod n256 */
    MB_FUNC_NAME(ifma_frommont52_n256_)(inv_skey, inv_skey);
}

/*
// compute r-component of the ECDSA signature
//
// r = ([skey]*G).x mod n256
//
// note: pay attention on skey[] representation
//       it should be transposed and zero expanded
*/
static __mb_mask nistp256_ecdsa_sign_r_mb8(U64 sign_r[], const U64 skey[], int8u pBuffer[])
{
    /* compute ephemeral public keys */
    P256_POINT P;

    MB_FUNC_NAME(ifma_ec_nistp256_mul_pointbase_)(&P, skey);

    /* extract affine P.x */
    MB_FUNC_NAME(ifma_aminv52_p256_)(P.Z, P.Z);    /* 1/Z   */
    MB_FUNC_NAME(ifma_ams52_p256_)(P.Z, P.Z);      /* 1/Z^2 */
    MB_FUNC_NAME(ifma_amm52_p256_)(P.X, P.X, P.Z); /* x = (X) * (1/Z^2) */

    /* convert x-coordinate to regular and then tp Montgomery n256 */
    MB_FUNC_NAME(ifma_frommont52_p256_)(P.X, P.X);
    MB_FUNC_NAME(ifma_fastred52_pn256_)(sign_r, P.X); /* fast reduction p => n */

    return MB_FUNC_NAME(is_zero_FE256_)(sign_r);
}

/*
// compute s-component of the ECDSA signature
//
// s = (inv_eph) * (msg + prv_skey*sign_r) mod n256
*/
static __mb_mask nistp256_ecdsa_sign_s_mb8(U64 sign_s[],
                                           U64 msg[],
                                           const U64 sign_r[],
                                           U64 inv_eph_skey[],
                                           U64 reg_skey[],
                                           int8u pBuffer[])
{
    __ALIGN64 U64 tmp[P256_LEN52];

    /* convert to Montgomery over n256 domain */
    MB_FUNC_NAME(ifma_tomont52_n256_)(inv_eph_skey, inv_eph_skey);
    MB_FUNC_NAME(ifma_tomont52_n256_)(tmp, sign_r);
    MB_FUNC_NAME(ifma_tomont52_n256_)(msg, msg);
    MB_FUNC_NAME(ifma_tomont52_n256_)(reg_skey, reg_skey);

    /* s = (inv_eph) * (msg + prv_skey*sign_r) mod n256 */
    MB_FUNC_NAME(ifma_amm52_n256_)(sign_s, reg_skey, tmp);
    MB_FUNC_NAME(ifma_add52_n256_)(sign_s, sign_s, msg);
    MB_FUNC_NAME(ifma_amm52_n256_)(sign_s, sign_s, inv_eph_skey);
    MB_FUNC_NAME(ifma_frommont52_n256_)(sign_s, sign_s);

    return MB_FUNC_NAME(is_zero_FE256_)(sign_s);
}

/*
// ECDSA signature verification algorithm
*/
static __mb_mask nistp256_ecdsa_verify_mb8(U64 sign_r[], U64 sign_s[], U64 msg[], P256_POINT* W)
{
    /* convert public key coords to Montgomery */
    MB_FUNC_NAME(ifma_tomont52_p256_)(W->X, W->X);
    MB_FUNC_NAME(ifma_tomont52_p256_)(W->Y, W->Y);
    MB_FUNC_NAME(ifma_tomont52_p256_)(W->Z, W->Z);

    __ALIGN64 U64 h1[P256_LEN52];
    __ALIGN64 U64 h2[P256_LEN52];

    /* h = (sign_s)^(-1) */
    MB_FUNC_NAME(ifma_tomont52_n256_)(sign_s, sign_s);
    MB_FUNC_NAME(ifma_aminv52_n256_)(sign_s, sign_s);
    /* h1 = msg * h */
    MB_FUNC_NAME(ifma_tomont52_n256_)(h1, msg);
    MB_FUNC_NAME(ifma_amm52_n256_)(h1, h1, sign_s);
    MB_FUNC_NAME(ifma_frommont52_n256_)(h1, h1);
    /* h2 = sign_r * h */
    MB_FUNC_NAME(ifma_tomont52_n256_)(h2, sign_r);
    MB_FUNC_NAME(ifma_amm52_n256_)(h2, h2, sign_s);
    MB_FUNC_NAME(ifma_frommont52_n256_)(h2, h2);

    int64u tmp[8][P256_LEN64];
    int64u* pa_tmp[8] = { tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7] };

    ifma_mb8_to_BNU(pa_tmp, (const int64u(*)[8])h1, P256_BITSIZE);
    ifma_BNU_transpose_copy((int64u(*)[8])h1, (const int64u(**))pa_tmp, P256_BITSIZE);

    ifma_mb8_to_BNU(pa_tmp, (const int64u(*)[8])h2, P256_BITSIZE);
    ifma_BNU_transpose_copy((int64u(*)[8])h2, (const int64u(**))pa_tmp, P256_BITSIZE);

    h1[P256_LEN64] = get_zero64();
    h2[P256_LEN64] = get_zero64();

    P256_POINT P;

    // P = h1*G + h2*W
    MB_FUNC_NAME(ifma_ec_nistp256_mul_point_)(W, W, h2);
    MB_FUNC_NAME(ifma_ec_nistp256_mul_pointbase_)(&P, h1);
    MB_FUNC_NAME(ifma_ec_nistp256_add_point_)(&P, &P, W);

    // P != 0
    __mb_mask signature_err_mask = MB_FUNC_NAME(is_zero_point_cordinate_)(P.Z);

    /* sign_r_restored = P.X mod n */
    __ALIGN64 U64 sign_r_restored[P256_LEN52];
    MB_FUNC_NAME(get_nistp256_ec_affine_coords_)(sign_r_restored, NULL, &P);
    MB_FUNC_NAME(ifma_frommont52_p256_)(sign_r_restored, sign_r_restored);
    MB_FUNC_NAME(ifma_fastred52_pn256_)(sign_r_restored, sign_r_restored);

    /* sign_r_restored != sign_r */
    signature_err_mask |= ~(MB_FUNC_NAME(cmp_eq_FE256_)(sign_r_restored, sign_r));

    return signature_err_mask;
}

mbx_status internal_avx512_nistp256_ecdsa_sign_setup_mb8(int64u* pa_inv_eph_skey[8],
                                                         int64u* pa_sign_rp[8],
                                                         const int64u* const pa_eph_skey[8],
                                                         int8u* pBuffer)
{
    mbx_status status = 0;
    /* convert keys into FE and compute inversion */
    U64 T[P256_LEN52];
    ifma_BNU_to_mb8((int64u(*)[8])T, pa_eph_skey, P256_BITSIZE);

    status |=
        MBX_SET_STS_BY_MASK(status, MB_FUNC_NAME(is_zero_FE256_)(T), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear key's inversion */
        MB_FUNC_NAME(zero_)((int64u(*)[8])T, sizeof(T) / sizeof(U64));
        return status;
    }

    nistp256_ecdsa_inv_keys_mb8(T, T, 0);
    /* return results in suitable format */
    ifma_mb8_to_BNU(pa_inv_eph_skey, (const int64u(*)[8])T, P256_BITSIZE);

    /* clear key's inversion */
    MB_FUNC_NAME(zero_)((int64u(*)[8])T, sizeof(T) / sizeof(U64));

    /* convert keys into scalars */
    U64 scalarz[P256_LEN64 + 1];
    ifma_BNU_transpose_copy((int64u(*)[8])scalarz, pa_eph_skey, P256_BITSIZE);
    scalarz[P256_LEN64] = get_zero64();
    /* compute r-component of the DSA signature */
    int8u stt_mask = nistp256_ecdsa_sign_r_mb8(T, scalarz, pBuffer);

    /* clear copy of the ephemeral secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])scalarz, sizeof(scalarz) / sizeof(U64));

    /* return results in suitable format */
    ifma_mb8_to_BNU(pa_sign_rp, (const int64u(*)[8])T, P256_BITSIZE);

    status |= MBX_SET_STS_BY_MASK(status, stt_mask, MBX_STATUS_SIGNATURE_ERR);
    return status;
}

mbx_status internal_avx512_nistp256_ecdsa_sign_complete_mb8(int8u* pa_sign_r[8],
                                                            int8u* pa_sign_s[8],
                                                            const int8u* const pa_msg[8],
                                                            const int64u* const pa_sign_rp[8],
                                                            const int64u* const pa_inv_eph_skey[8],
                                                            const int64u* const pa_reg_skey[8],
                                                            int8u* pBuffer)
{
    mbx_status status = 0;
    __ALIGN64 U64 inv_eph[P256_LEN52];
    __ALIGN64 U64 reg_skey[P256_LEN52];
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];
    __ALIGN64 U64 msg[P256_LEN52];

    /* convert inv_eph, reg_skey, sign_r and message to mb format */

    ifma_BNU_to_mb8((int64u(*)[8])inv_eph, pa_inv_eph_skey, P256_BITSIZE);
    ifma_BNU_to_mb8((int64u(*)[8])reg_skey, pa_reg_skey, P256_BITSIZE);
    ifma_BNU_to_mb8((int64u(*)[8])sign_r, pa_sign_rp, P256_BITSIZE);
    ifma_HexStr8_to_mb8((int64u(*)[8])msg, pa_msg, P256_BITSIZE);

    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(inv_eph), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(reg_skey), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(sign_r), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(msg), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear copy of the ephemeral secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])inv_eph, sizeof(inv_eph) / sizeof(U64));
        /* clear copy of the regular secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])reg_skey, sizeof(reg_skey) / sizeof(U64));
        return status;
    }

    /* compute s- signature component: s = (inv_eph) * (msg + prv_skey*sign_r) mod n256 */
    nistp256_ecdsa_sign_s_mb8(sign_s, msg, sign_r, inv_eph, reg_skey, pBuffer);

    /* clear copy of the ephemeral secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])inv_eph, sizeof(inv_eph) / sizeof(U64));
    /* clear copy of the regular secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])reg_skey, sizeof(reg_skey) / sizeof(U64));

    /* check if sign_r!=0 and sign_s!=0 */
    int8u stt_mask_r = MB_FUNC_NAME(is_zero_FE256_)(sign_r);
    int8u stt_mask_s = MB_FUNC_NAME(is_zero_FE256_)(sign_s);

    /* convert sign_r and sing_s to strings */
    ifma_mb8_to_HexStr8(pa_sign_r, (const int64u(*)[8])sign_r, P256_BITSIZE);
    ifma_mb8_to_HexStr8(pa_sign_s, (const int64u(*)[8])sign_s, P256_BITSIZE);

    status |= MBX_SET_STS_BY_MASK(status, stt_mask_r, MBX_STATUS_SIGNATURE_ERR);
    status |= MBX_SET_STS_BY_MASK(status, stt_mask_s, MBX_STATUS_SIGNATURE_ERR);
    return status;
}

mbx_status internal_avx512_nistp256_ecdsa_sign_mb8(int8u* pa_sign_r[8],
                                                   int8u* pa_sign_s[8],
                                                   const int8u* const pa_msg[8],
                                                   const int64u* const pa_eph_skey[8],
                                                   const int64u* const pa_reg_skey[8],
                                                   int8u* pBuffer)
{
    mbx_status status = 0;
    __ALIGN64 U64 inv_eph_key[P256_LEN52];
    __ALIGN64 U64 reg_key[P256_LEN52];
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];
    __ALIGN64 U64 scalar[P256_LEN64 + 1];
    __ALIGN64 U64 msg[P256_LEN52];

    /* convert ephemeral keys into FE */
    ifma_BNU_to_mb8((int64u(*)[8])inv_eph_key, pa_eph_skey, P256_BITSIZE);
    /* convert epphemeral keys into scalar */
    ifma_BNU_transpose_copy((int64u(*)[8])scalar, pa_eph_skey, P256_BITSIZE);
    scalar[P256_LEN64] = get_zero64();
    /* convert reg_skey */
    ifma_BNU_to_mb8((int64u(*)[8])reg_key, pa_reg_skey, P256_BITSIZE);
    /* convert message */
    ifma_HexStr8_to_mb8((int64u(*)[8])msg, pa_msg, P256_BITSIZE);

    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(inv_eph_key), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(reg_key), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(msg), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear copy of the ephemeral secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])inv_eph_key, sizeof(inv_eph_key) / sizeof(U64));
        MB_FUNC_NAME(zero_)((int64u(*)[8])scalar, sizeof(scalar) / sizeof(U64));
        /* clear copy of the regular secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])reg_key, sizeof(reg_key) / sizeof(U64));
        return status;
    }

    /* compute inversion */
    nistp256_ecdsa_inv_keys_mb8(inv_eph_key, inv_eph_key, pBuffer);
    /* compute r-component */
    nistp256_ecdsa_sign_r_mb8(sign_r, scalar, pBuffer);
    /* compute s-component */
    nistp256_ecdsa_sign_s_mb8(sign_s, msg, sign_r, inv_eph_key, reg_key, pBuffer);

    /* clear copy of the ephemeral secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])inv_eph_key, sizeof(inv_eph_key) / sizeof(U64));
    MB_FUNC_NAME(zero_)((int64u(*)[8])scalar, sizeof(scalar) / sizeof(U64));

    /* clear copy of the regular secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])reg_key, sizeof(reg_key) / sizeof(U64));

    /* check if sign_r!=0 and sign_s!=0 */
    int8u stt_mask_r = MB_FUNC_NAME(is_zero_FE256_)(sign_r);
    int8u stt_mask_s = MB_FUNC_NAME(is_zero_FE256_)(sign_s);

    /* convert signature components to strings */
    ifma_mb8_to_HexStr8(pa_sign_r, (const int64u(*)[8])sign_r, P256_BITSIZE);
    ifma_mb8_to_HexStr8(pa_sign_s, (const int64u(*)[8])sign_s, P256_BITSIZE);

    status |= MBX_SET_STS_BY_MASK(status, stt_mask_r, MBX_STATUS_SIGNATURE_ERR);
    status |= MBX_SET_STS_BY_MASK(status, stt_mask_s, MBX_STATUS_SIGNATURE_ERR);
    return status;
}

mbx_status internal_avx512_nistp256_ecdsa_verify_mb8(const int8u* const pa_sign_r[8],
                                                     const int8u* const pa_sign_s[8],
                                                     const int8u* const pa_msg[8],
                                                     const int64u* const pa_pubx[8],
                                                     const int64u* const pa_puby[8],
                                                     const int64u* const pa_pubz[8],
                                                     int8u* pBuffer,
                                                     int use_jproj_coords)
{
    mbx_status status = 0;
    __ALIGN64 U64 msg[P256_LEN52];
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];

    /* convert input params */
    ifma_HexStr8_to_mb8((int64u(*)[8])msg, pa_msg, P256_BITSIZE);
    ifma_HexStr8_to_mb8((int64u(*)[8])sign_r, pa_sign_r, P256_BITSIZE);
    ifma_HexStr8_to_mb8((int64u(*)[8])sign_s, pa_sign_s, P256_BITSIZE);

    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(msg), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(sign_r), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(sign_s), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    P256_POINT W;

    ifma_BNU_to_mb8((int64u(*)[8])W.X, (const int64u*(*))pa_pubx, P256_BITSIZE);
    ifma_BNU_to_mb8((int64u(*)[8])W.Y, (const int64u*(*))pa_puby, P256_BITSIZE);
    if (use_jproj_coords)
        ifma_BNU_to_mb8((int64u(*)[8])W.Z, (const int64u*(*))pa_pubz, P256_BITSIZE);
    else
        MB_FUNC_NAME(mov_FE256_)(W.Z, (U64*)ones);

    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_p256_)(W.X), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_p256_)(W.Y), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_p256_)(W.Z), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    __mb_mask signature_err_mask = nistp256_ecdsa_verify_mb8(sign_r, sign_s, msg, &W);
    status |= MBX_SET_STS_BY_MASK(status, signature_err_mask, MBX_STATUS_SIGNATURE_ERR);
    return status;
}


/*
// OpenSSL's specific implementations
*/
#ifndef BN_OPENSSL_DISABLE

static void reverse_inplace(int8u* inpout, int len)
{
    int mudpoint = len / 2;
    for (int n = 0; n < mudpoint; n++) {
        int x               = inpout[n];
        inpout[n]           = inpout[len - 1 - n];
        inpout[len - 1 - n] = x;
    }
}

static BIGNUM* BN_bnu2bn(int64u* val, int len, BIGNUM* ret)
{
    len = len * sizeof(int64u);
    reverse_inplace((int8u*)val, len);
    ret = BN_bin2bn((int8u*)val, len, ret);
    reverse_inplace((int8u*)val, len);
    return ret;
}

static void ifma_mb8_to_BN_256(BIGNUM* out_bn[8], const int64u inp_mb8[][8])
{
    int64u tmp[8][P256_LEN64];
    int64u* pa_tmp[8] = { tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7] };
    /* convert to plain data */
    ifma_mb8_to_BNU(pa_tmp, (const int64u(*)[8])inp_mb8, P256_BITSIZE);

    for (int nb = 0; nb < 8; nb++)
        out_bn[nb] = BN_bnu2bn(tmp[nb], P256_LEN64, out_bn[nb]);
}

mbx_status internal_avx512_nistp256_ecdsa_sign_setup_ssl_mb8(BIGNUM* pa_inv_skey[8],
                                                             BIGNUM* pa_sign_rp[8],
                                                             const BIGNUM* const pa_eph_skey[8],
                                                             int8u* pBuffer)
{
    mbx_status status = 0;
    /* convert keys into FE and compute inversion */
    U64 T[P256_LEN52];
    ifma_BN_to_mb8((int64u(*)[8])T, pa_eph_skey, P256_BITSIZE);

    status |=
        MBX_SET_STS_BY_MASK(status, MB_FUNC_NAME(is_zero_FE256_)(T), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear key's inversion */
        MB_FUNC_NAME(zero_)((int64u(*)[8])T, sizeof(T) / sizeof(U64));
        return status;
    }

    nistp256_ecdsa_inv_keys_mb8(T, T, 0);
    /* store results in suitable format */
    ifma_mb8_to_BN_256(pa_inv_skey, (const int64u(*)[8])T);

    /* clear key's inversion */
    MB_FUNC_NAME(zero_)((int64u(*)[8])T, sizeof(T) / sizeof(U64));

    /* convert keys into scalars */
    U64 scalarz[P256_LEN64 + 1];
    ifma_BN_transpose_copy((int64u(*)[8])scalarz, pa_eph_skey, P256_BITSIZE);
    scalarz[P256_LEN64] = get_zero64();
    /* compute r-component of the DSA signature */
    int8u stt_mask = nistp256_ecdsa_sign_r_mb8(T, scalarz, pBuffer);

    /* clear copy of the ephemeral secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])scalarz, sizeof(scalarz) / sizeof(U64));

    /* store results in suitable format */
    ifma_mb8_to_BN_256(pa_sign_rp, (const int64u(*)[8])T);

    status |= MBX_SET_STS_BY_MASK(status, stt_mask, MBX_STATUS_SIGNATURE_ERR);
    return 0;
}

mbx_status internal_avx512_nistp256_ecdsa_sign_complete_ssl_mb8(
    int8u* pa_sign_r[8],
    int8u* pa_sign_s[8],
    const int8u* const pa_msg[8],
    const BIGNUM* const pa_sign_rp[8],
    const BIGNUM* const pa_inv_eph_skey[8],
    const BIGNUM* const pa_reg_skey[8],
    int8u* pBuffer)
{
    mbx_status status = 0;
    __ALIGN64 U64 inv_eph[P256_LEN52];
    __ALIGN64 U64 reg_skey[P256_LEN52];
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];
    __ALIGN64 U64 msg[P256_LEN52];

    /* convert inv_eph, reg_skey, sign_r and message to mb format */
    ifma_BN_to_mb8((int64u(*)[8])inv_eph, pa_inv_eph_skey, P256_BITSIZE);
    ifma_BN_to_mb8((int64u(*)[8])reg_skey, pa_reg_skey, P256_BITSIZE);
    ifma_BN_to_mb8((int64u(*)[8])sign_r, pa_sign_rp, P256_BITSIZE);
    ifma_HexStr8_to_mb8((int64u(*)[8])msg, pa_msg, P256_BITSIZE);

    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(inv_eph), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(reg_skey), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(sign_r), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(msg), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear copy of the ephemeral secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])inv_eph, sizeof(inv_eph) / sizeof(U64));
        /* clear copy of the regular secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])reg_skey, sizeof(reg_skey) / sizeof(U64));
        return status;
    }

    /* compute s- signature component: s = (inv_eph) * (msg + prv_skey*sign_r) mod n256 */
    nistp256_ecdsa_sign_s_mb8(sign_s, msg, sign_r, inv_eph, reg_skey, pBuffer);

    /* clear copy of the ephemeral secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])inv_eph, sizeof(inv_eph) / sizeof(U64));
    /* clear copy of the regular secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])reg_skey, sizeof(reg_skey) / sizeof(U64));

    /* convert sign_r and sing_s to strings */
    ifma_mb8_to_HexStr8(pa_sign_r, (const int64u(*)[8])sign_r, P256_BITSIZE);
    ifma_mb8_to_HexStr8(pa_sign_s, (const int64u(*)[8])sign_s, P256_BITSIZE);

    /* check if sign_r!=0 and sign_s!=0 */
    int8u stt_mask_r = MB_FUNC_NAME(is_zero_FE256_)(sign_r);
    int8u stt_mask_s = MB_FUNC_NAME(is_zero_FE256_)(sign_s);
    status |= MBX_SET_STS_BY_MASK(status, stt_mask_r, MBX_STATUS_SIGNATURE_ERR);
    status |= MBX_SET_STS_BY_MASK(status, stt_mask_s, MBX_STATUS_SIGNATURE_ERR);
    return 0;
}

mbx_status internal_avx512_nistp256_ecdsa_sign_ssl_mb8(int8u* pa_sign_r[8],
                                                       int8u* pa_sign_s[8],
                                                       const int8u* const pa_msg[8],
                                                       const BIGNUM* const pa_eph_skey[8],
                                                       const BIGNUM* const pa_reg_skey[8],
                                                       int8u* pBuffer)
{
    mbx_status status = 0;
    __ALIGN64 U64 inv_eph_key[P256_LEN52];
    __ALIGN64 U64 reg_key[P256_LEN52];
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];
    __ALIGN64 U64 scalar[P256_LEN64 + 1];
    __ALIGN64 U64 msg[P256_LEN52];

    /* convert ephemeral keys into FE */
    ifma_BN_to_mb8((int64u(*)[8])inv_eph_key, pa_eph_skey, P256_BITSIZE);
    /* convert epphemeral keys into scalar */
    ifma_BN_transpose_copy((int64u(*)[8])scalar, pa_eph_skey, P256_BITSIZE);
    scalar[P256_LEN64] = get_zero64();
    /* convert reg_skey */
    ifma_BN_to_mb8((int64u(*)[8])reg_key, pa_reg_skey, P256_BITSIZE);
    /* convert message */
    ifma_HexStr8_to_mb8((int64u(*)[8])msg, pa_msg, P256_BITSIZE);

    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(inv_eph_key), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(is_zero_FE256_)(reg_key), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(msg), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear copy of the ephemeral secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])inv_eph_key, sizeof(inv_eph_key) / sizeof(U64));
        MB_FUNC_NAME(zero_)((int64u(*)[8])scalar, sizeof(scalar) / sizeof(U64));
        /* clear copy of the regular secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])reg_key, sizeof(reg_key) / sizeof(U64));
        return status;
    }

    /* compute inversion */
    nistp256_ecdsa_inv_keys_mb8(inv_eph_key, inv_eph_key, pBuffer);
    /* compute r-component */
    nistp256_ecdsa_sign_r_mb8(sign_r, scalar, pBuffer);
    /* compute s-component */
    nistp256_ecdsa_sign_s_mb8(sign_s, msg, sign_r, inv_eph_key, reg_key, pBuffer);

    /* clear copy of the ephemeral secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])inv_eph_key, sizeof(inv_eph_key) / sizeof(U64));
    MB_FUNC_NAME(zero_)((int64u(*)[8])scalar, sizeof(scalar) / sizeof(U64));

    /* clear copy of the regular secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])reg_key, sizeof(reg_key) / sizeof(U64));

    /* convert signature components to strings */
    ifma_mb8_to_HexStr8(pa_sign_r, (const int64u(*)[8])sign_r, P256_BITSIZE);
    ifma_mb8_to_HexStr8(pa_sign_s, (const int64u(*)[8])sign_s, P256_BITSIZE);

    /* check if sign_r!=0 and sign_s!=0 */
    int8u stt_mask_r = MB_FUNC_NAME(is_zero_FE256_)(sign_r);
    int8u stt_mask_s = MB_FUNC_NAME(is_zero_FE256_)(sign_s);
    status |= MBX_SET_STS_BY_MASK(status, stt_mask_r, MBX_STATUS_SIGNATURE_ERR);
    status |= MBX_SET_STS_BY_MASK(status, stt_mask_s, MBX_STATUS_SIGNATURE_ERR);
    return status;
}

mbx_status internal_avx512_nistp256_ecdsa_verify_ssl_mb8(const ECDSA_SIG* const pa_sig[8],
                                                         const int8u* const pa_msg[8],
                                                         const BIGNUM* const pa_pubx[8],
                                                         const BIGNUM* const pa_puby[8],
                                                         const BIGNUM* const pa_pubz[8],
                                                         int8u* pBuffer,
                                                         int use_jproj_coords)
{
    mbx_status status    = 0;
    BIGNUM* pa_sign_r[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    BIGNUM* pa_sign_s[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    for (int buf_no = 0; buf_no < 8; buf_no++) {
        if (pa_sig[buf_no] != NULL) {
            ECDSA_SIG_get0(pa_sig[buf_no],
                           (const BIGNUM(**))pa_sign_r + buf_no,
                           (const BIGNUM(**))pa_sign_s + buf_no);
        }
    }

    __ALIGN64 U64 msg[P256_LEN52];
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];

    /* convert input params */
    ifma_HexStr8_to_mb8((int64u(*)[8])msg, pa_msg, P256_BITSIZE);
    ifma_BN_to_mb8((int64u(*)[8])sign_r, (const BIGNUM(**))pa_sign_r, P256_BITSIZE);
    ifma_BN_to_mb8((int64u(*)[8])sign_s, (const BIGNUM(**))pa_sign_s, P256_BITSIZE);

    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(msg), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(sign_r), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_n256_)(sign_s), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    P256_POINT W;

    ifma_BN_to_mb8((int64u(*)[8])W.X, pa_pubx, P256_BITSIZE);
    ifma_BN_to_mb8((int64u(*)[8])W.Y, pa_puby, P256_BITSIZE);
    if (use_jproj_coords)
        ifma_BN_to_mb8((int64u(*)[8])W.Z, pa_pubz, P256_BITSIZE);
    else
        MB_FUNC_NAME(mov_FE256_)(W.Z, (U64*)ones);

    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_p256_)(W.X), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_p256_)(W.Y), MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_SET_STS_BY_MASK(
        status, MB_FUNC_NAME(ifma_check_range_p256_)(W.Z), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    __mb_mask signature_err_mask = nistp256_ecdsa_verify_mb8(sign_r, sign_s, msg, &W);
    status |= MBX_SET_STS_BY_MASK(status, signature_err_mask, MBX_STATUS_SIGNATURE_ERR);
    return status;
}

#endif // BN_OPENSSL_DISABLE

#endif /* #if (_MBX>=_MBX_K1) */
