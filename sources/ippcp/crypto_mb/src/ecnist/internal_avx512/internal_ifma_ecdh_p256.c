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

#include <crypto_mb/status.h>

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_cvt52.h>
#include <internal/ecnist/ifma_ecpoint_p256.h>
#include <internal/rsa/ifma_rsa_arith.h>

#if (_MBX >= _MBX_K1)

#ifndef BN_OPENSSL_DISABLE
#include <openssl/bn.h>

mbx_status internal_avx512_mbx_nistp256_ecdh_ssl_mb8(int8u* pa_shared_key[8],
                                                     const BIGNUM* const pa_skey[8],
                                                     const BIGNUM* const pa_pubx[8],
                                                     const BIGNUM* const pa_puby[8],
                                                     const BIGNUM* const pa_pubz[8],
                                                     int8u* pBuffer,
                                                     int use_jproj_coords)
{
    mbx_status status = 0;
    /* zero padded private keys */
    U64 secretz[P256_LEN64 + 1];
    ifma_BN_transpose_copy((int64u(*)[8])secretz, (const BIGNUM**)pa_skey, P256_BITSIZE);
    secretz[P256_LEN64] = get_zero64();

    status |= MBX_SET_STS_BY_MASK(
        status, is_zero(secretz, P256_LEN64 + 1), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear copy of the secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])secretz, sizeof(secretz) / sizeof(U64));
        return status;
    }

    P256_POINT P;
    /* set party's public */
    ifma_BN_to_mb8((int64u(*)[8])P.X, (const BIGNUM*(*))pa_pubx, P256_BITSIZE); /* P-> radix 2^52 */
    ifma_BN_to_mb8((int64u(*)[8])P.Y, (const BIGNUM*(*))pa_puby, P256_BITSIZE);
    if (use_jproj_coords)
        ifma_BN_to_mb8((int64u(*)[8])P.Z, (const BIGNUM*(*))pa_pubz, P256_BITSIZE);
    else
        MB_FUNC_NAME(mov_FE256_)(P.Z, (U64*)ones);
    /* convert to Montgomery */
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.X, P.X);
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.Y, P.Y);
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.Z, P.Z);

    /* check if P does not belong to EC */
    __mb_mask not_on_curve_mask = ~MB_FUNC_NAME(ifma_is_on_curve_p256_)(&P, use_jproj_coords);
    /* set points out of EC to infinity */
    MB_FUNC_NAME(mask_set_point_to_infinity_)(&P, not_on_curve_mask);
    /* update status */
    status |= MBX_SET_STS_BY_MASK(status, not_on_curve_mask, MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear copy of the secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])secretz, sizeof(secretz) / sizeof(U64));
        return status;
    }

    P256_POINT R;
    /* compute R = [secretz]*P */
    MB_FUNC_NAME(ifma_ec_nistp256_mul_point_)(&R, &P, secretz);

    /* clear copy of the secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])secretz, sizeof(secretz) / sizeof(U64));

    /* return affine R.x */
    __ALIGN64 U64 Z2[P256_LEN52];
    ifma_aminv52_p256_mb8(Z2, R.Z);    /* 1/Z   */
    ifma_ams52_p256_mb8(Z2, Z2);       /* 1/Z^2 */
    ifma_amm52_p256_mb8(R.X, R.X, Z2); /* x = (X) * (1/Z^2) */
    /* to regular domain */
    MB_FUNC_NAME(ifma_frommont52_p256_)(R.X, R.X);

    /* store result */
    ifma_mb8_to_HexStr8(pa_shared_key, (const int64u(*)[8])R.X, P256_BITSIZE);

    /* clear computed shared keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])(&R), sizeof(R) / sizeof(U64));

    return status;
}

#endif // BN_OPENSSL_DISABLE

mbx_status internal_avx512_nistp256_ecdh_mb8(int8u* pa_shared_key[8],
                                             const int64u* const pa_skey[8],
                                             const int64u* const pa_pubx[8],
                                             const int64u* const pa_puby[8],
                                             const int64u* const pa_pubz[8],
                                             int8u* pBuffer,
                                             int use_jproj_coords)
{
    mbx_status status = 0;
    /* zero padded private keys */
    U64 secretz[P256_LEN64 + 1];
    ifma_BNU_transpose_copy((int64u(*)[8])secretz, (const int64u**)pa_skey, P256_BITSIZE);
    secretz[P256_LEN64] = get_zero64();

    status |= MBX_SET_STS_BY_MASK(
        status, is_zero(secretz, P256_LEN64 + 1), MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear copy of the secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])secretz, sizeof(secretz) / sizeof(U64));
        return status;
    }

    P256_POINT P;
    /* set party's public */
    ifma_BNU_to_mb8(
        (int64u(*)[8])P.X, (const int64u*(*))pa_pubx, P256_BITSIZE); // P-> crypto_mb radix 2^52
    ifma_BNU_to_mb8((int64u(*)[8])P.Y, (const int64u*(*))pa_puby, P256_BITSIZE);
    if (use_jproj_coords)
        ifma_BNU_to_mb8((int64u(*)[8])P.Z, (const int64u*(*))pa_pubz, P256_BITSIZE);
    else
        MB_FUNC_NAME(mov_FE256_)(P.Z, (U64*)ones);
    /* convert to Montgomery */
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.X, P.X);
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.Y, P.Y);
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.Z, P.Z);

    /* check if P does not belong to EC */
    __mb_mask not_on_curve_mask = ~MB_FUNC_NAME(ifma_is_on_curve_p256_)(&P, use_jproj_coords);
    /* set points out of EC to infinity */
    MB_FUNC_NAME(mask_set_point_to_infinity_)(&P, not_on_curve_mask);
    /* update status */
    status |= MBX_SET_STS_BY_MASK(status, not_on_curve_mask, MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear copy of the secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[8])secretz, sizeof(secretz) / sizeof(U64));
        return status;
    }

    P256_POINT R;
    /* compute R = [secretz]*P */
    MB_FUNC_NAME(ifma_ec_nistp256_mul_point_)(&R, &P, secretz);

    /* clear copy of the secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])secretz, sizeof(secretz) / sizeof(U64));

    /* return affine R.x */
    __ALIGN64 U64 Z2[P256_LEN52];
    ifma_aminv52_p256_mb8(Z2, R.Z);    /* 1/Z   */
    ifma_ams52_p256_mb8(Z2, Z2);       /* 1/Z^2 */
    ifma_amm52_p256_mb8(R.X, R.X, Z2); /* x = (X) * (1/Z^2) */
    /* to regular domain */
    MB_FUNC_NAME(ifma_frommont52_p256_)(R.X, R.X);

    /* store result */
    ifma_mb8_to_HexStr8(pa_shared_key, (const int64u(*)[8])R.X, P256_BITSIZE);

    /* clear computed shared keys */
    MB_FUNC_NAME(zero_)((int64u(*)[8])(&R), sizeof(R) / sizeof(U64));

    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
