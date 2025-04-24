/*************************************************************************
* Copyright (C) 2025 Intel Corporation
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

#if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED))

/*
// ECDSA signature verification kernel
// sign_r           input r-component of the signature (regular domain)
// sign_s           input s-component of the signature (regular domain)
// pa_msg           input message representation (regular domain)
// W                input point (pubx, puby, pubz) (regular domain)
//
*/
static __mb_mask MB_FUNC_NAME(nistp256_ecdsa_verify_)(U64 sign_r[],
                                                      U64 sign_s[],
                                                      U64 msg[],
                                                      P256_POINT* W)
{
    /* Convert public key coords to Montgomery */
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

    int64u tmp[MB_WIDTH][P256_LEN64];
    int64u* pa_tmp[MB_WIDTH];
    for (int32u idx = 0; idx < MB_WIDTH; idx++)
        pa_tmp[idx] = tmp[idx];

    /* Convert scalars h1, h2 from radix^52 mb to radix^64 mb */
    ifma_mb_to_BNU(pa_tmp, (const int64u(*)[MB_WIDTH])h1, P256_BITSIZE);
    ifma_BNU_transpose_copy((int64u(*)[MB_WIDTH])h1, (const int64u(**))pa_tmp, P256_BITSIZE);
    ifma_mb_to_BNU(pa_tmp, (const int64u(*)[MB_WIDTH])h2, P256_BITSIZE);
    ifma_BNU_transpose_copy((int64u(*)[MB_WIDTH])h2, (const int64u(**))pa_tmp, P256_BITSIZE);

    h1[P256_LEN64] = get_zero64();
    h2[P256_LEN64] = get_zero64();

    P256_POINT P;

    /* P = h1*G + h2*W */
    MB_FUNC_NAME(ifma_ec_nistp256_mul_point_)(W, W, h2);
    MB_FUNC_NAME(ifma_ec_nistp256_mul_pointbase_)(&P, h1);
    MB_FUNC_NAME(ifma_ec_nistp256_add_point_)(&P, &P, W);

    /* P != 0 */
    __mb_mask signature_err_mask = MB_FUNC_NAME(is_zero_point_cordinate_)(P.Z);

    /* sign_r_restored = P.X mod n */
    __ALIGN64 U64 sign_r_restored[P256_LEN52];
    MB_FUNC_NAME(get_nistp256_ec_affine_coords_)(sign_r_restored, NULL, &P);
    MB_FUNC_NAME(ifma_frommont52_p256_)(sign_r_restored, sign_r_restored);
    MB_FUNC_NAME(ifma_fastred52_pn256_)(sign_r_restored, sign_r_restored);

    /* sign_r_restored != sign_r */
    signature_err_mask =
        or_mb_mask(signature_err_mask,
                   not_mb_mask((MB_FUNC_NAME(cmp_eq_FE256_)(sign_r_restored, sign_r))));

    return signature_err_mask;
}

/*
// Internal (layer 2) verify function
// pa_sign_r        input r-component of the signature
// pa_sign_s        input s-component of the signature
// pa_msg           input message representation
// pa_pubx          input pub key x coordinate
// pa_puby          input pub key y coordinate
// pa_pubz          input pub key z coordinate
// pBuffer          input working buffer, currently unused
// use_jproj_coords input flag specifying the type of the pub key point
//
//      h = s^–1(mod n); h1 = msg*h(mod n); h2 = r*h(mod n)
//      P = h1*G + h2*W
//      r1 = P.x(mod n)
//      r1 == r?
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_verify_)(const int8u* const pa_sign_r[MB_WIDTH],
                                                         const int8u* const pa_sign_s[MB_WIDTH],
                                                         const int8u* const pa_msg[MB_WIDTH],
                                                         const int64u* const pa_pubx[MB_WIDTH],
                                                         const int64u* const pa_puby[MB_WIDTH],
                                                         const int64u* const pa_pubz[MB_WIDTH],
                                                         int8u* pBuffer,
                                                         int use_jproj_coords)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);

    mbx_status status = 0;

    __ALIGN64 U64 msg[P256_LEN52];
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];

    /* Convert input params into radix 2^52 */
    ifma_HexStr_to_mb((int64u(*)[MB_WIDTH])msg, pa_msg, P256_BITSIZE);
    ifma_HexStr_to_mb((int64u(*)[MB_WIDTH])sign_r, pa_sign_r, P256_BITSIZE);
    ifma_HexStr_to_mb((int64u(*)[MB_WIDTH])sign_s, pa_sign_s, P256_BITSIZE);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(msg),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(sign_r),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(sign_s),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    /* Construct point W from the input */
    P256_POINT W;
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])W.X, (const int64u*(*))pa_pubx, P256_BITSIZE);
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])W.Y, (const int64u*(*))pa_puby, P256_BITSIZE);
    if (use_jproj_coords)
        ifma_BNU_to_mb((int64u(*)[MB_WIDTH])W.Z, (const int64u*(*))pa_pubz, P256_BITSIZE);
    else
        MB_FUNC_NAME(mov_FE256_)(W.Z, (U64*)ones);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_p256_)(W.X),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_p256_)(W.Y),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_p256_)(W.Z),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    /* Get the result "valid"/"invalid" */
    __mb_mask signature_err_mask = MB_FUNC_NAME(nistp256_ecdsa_verify_)(sign_r, sign_s, msg, &W);
    status |= MBX_STS_BY_MASK_GENERIC(status, signature_err_mask, MBX_STATUS_SIGNATURE_ERR);

    return status;
}

//----------------------------------------------
//      OpenSSL's specific implementations
//----------------------------------------------

#ifndef BN_OPENSSL_DISABLE

/*
// Internal (layer 2) verify function, ssl-specific API
// pa_sig           input signature (r,s)
// pa_msg           input message representation
// pa_pubx          input BIGNUMs with pub key x coordinate
// pa_puby          input BIGNUMs with pub key y coordinate
// pa_pubz          input BIGNUMs with pub key z coordinate
// pBuffer          input working buffer, currently unused
// use_jproj_coords input flag specifying the type of the pub key point
//
//      h = s^–1(mod n); h1 = msg*h(mod n); h2 = r*h(mod n)
//      P = h1*G + h2*W
//      r1 = P.x(mod n)
//      r1 == r?
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_verify_ssl_)(
    const ECDSA_SIG* const pa_sig[MB_WIDTH],
    const int8u* const pa_msg[MB_WIDTH],
    const BIGNUM* const pa_pubx[MB_WIDTH],
    const BIGNUM* const pa_puby[MB_WIDTH],
    const BIGNUM* const pa_pubz[MB_WIDTH],
    int8u* pBuffer,
    int use_jproj_coords)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);

    mbx_status status           = 0;
    BIGNUM* pa_sign_r[MB_WIDTH] = { REP_NUM_BUFF_DECL(NULL) };
    BIGNUM* pa_sign_s[MB_WIDTH] = { REP_NUM_BUFF_DECL(NULL) };

    for (int buf_no = 0; buf_no < MB_WIDTH; buf_no++) {
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
    ifma_HexStr_to_mb((int64u(*)[MB_WIDTH])msg, pa_msg, P256_BITSIZE);
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])sign_r, (const BIGNUM(**))pa_sign_r, P256_BITSIZE);
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])sign_s, (const BIGNUM(**))pa_sign_s, P256_BITSIZE);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(msg),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(sign_r),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(sign_s),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    P256_POINT W;

    ifma_BN_to_mb((int64u(*)[MB_WIDTH])W.X, pa_pubx, P256_BITSIZE);
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])W.Y, pa_puby, P256_BITSIZE);
    if (use_jproj_coords)
        ifma_BN_to_mb((int64u(*)[MB_WIDTH])W.Z, pa_pubz, P256_BITSIZE);
    else
        MB_FUNC_NAME(mov_FE256_)(W.Z, (U64*)ones);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_p256_)(W.X),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_p256_)(W.Y),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_p256_)(W.Z),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    __mb_mask signature_err_mask = MB_FUNC_NAME(nistp256_ecdsa_verify_)(sign_r, sign_s, msg, &W);
    status |= MBX_STS_BY_MASK_GENERIC(status, signature_err_mask, MBX_STATUS_SIGNATURE_ERR);

    return status;
}

#endif /* BN_OPENSSL_DISABLE */

#endif /* #if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)) */
