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

#include <crypto_mb/status.h>

#include <internal/common/ifma_defs.h>
#include <internal/common/ifma_cvt52.h>
#include <internal/ecnist/ifma_ecpoint_p256.h>
#include <internal/rsa/ifma_rsa_arith.h>

#ifndef BN_OPENSSL_DISABLE
#include <openssl/bn.h>
#endif /* BN_OPENSSL_DISABLE */

#if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED))

/*
// Internal (layer 2) DH function
// pa_shared_key    output computed shared secret
// pa_skey          input secret key value
// pa_pubx          input pub key x coordinate
// pa_puby          input pub key y coordinate
// pa_pubz          input pub key z coordinate
// pBuffer          input working buffer, currently unused
// use_jproj_coords input flag specifying the type of the pub key point
//
//      P = skey*W
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecdh_)(int8u* pa_shared_key[MB_WIDTH],
                                                 const int64u* const pa_skey[MB_WIDTH],
                                                 const int64u* const pa_pubx[MB_WIDTH],
                                                 const int64u* const pa_puby[MB_WIDTH],
                                                 const int64u* const pa_pubz[MB_WIDTH],
                                                 int8u* pBuffer,
                                                 int use_jproj_coords)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);

    mbx_status status = 0;

    /* Zero padded private keys in radix 2^64 */
    U64 secretz[P256_LEN64 + 1];
    ifma_BNU_transpose_copy((int64u(*)[MB_WIDTH])secretz, (const int64u**)pa_skey, P256_BITSIZE);
    secretz[P256_LEN64] = get_zero64();

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      is_zero(secretz, P256_LEN64 + 1),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* Сlear copy of the secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])secretz, sizeof(secretz) / sizeof(U64));
        return status;
    }

    /* Construct party's public point(P-> crypto_mb radix 2^52) */
    P256_POINT P;
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])P.X, (const int64u*(*))pa_pubx, P256_BITSIZE);
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])P.Y, (const int64u*(*))pa_puby, P256_BITSIZE);
    if (use_jproj_coords)
        ifma_BNU_to_mb((int64u(*)[MB_WIDTH])P.Z, (const int64u*(*))pa_pubz, P256_BITSIZE);
    else
        MB_FUNC_NAME(mov_FE256_)(P.Z, (U64*)ones);

    /* Convert to Montgomery */
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.X, P.X);
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.Y, P.Y);
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.Z, P.Z);

    /* Check if P does not belong to EC */
    __mb_mask not_on_curve_mask =
        not_mb_mask(MB_FUNC_NAME(ifma_is_on_curve_p256_)(&P, use_jproj_coords));
    /* Set points out of EC to infinity and update status*/
    MB_FUNC_NAME(mask_set_point_to_infinity_)(&P, not_on_curve_mask);
    status |= MBX_STS_BY_MASK_GENERIC(status, not_on_curve_mask, MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* Сlear copy of the secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])secretz, sizeof(secretz) / sizeof(U64));
        return status;
    }

    /* Сompute R = [secretz]*P */
    P256_POINT R;
    MB_FUNC_NAME(ifma_ec_nistp256_mul_point_)(&R, &P, secretz);

    /* Clear copy of the secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])secretz, sizeof(secretz) / sizeof(U64));

    /* Return affine R.x */
    __ALIGN64 U64 Z2[P256_LEN52];
    MB_FUNC_NAME(ifma_aminv52_p256_)(Z2, R.Z);    /* 1/Z   */
    MB_FUNC_NAME(ifma_ams52_p256_)(Z2, Z2);       /* 1/Z^2 */
    MB_FUNC_NAME(ifma_amm52_p256_)(R.X, R.X, Z2); /* x = (X) * (1/Z^2) */

    /* Move to regular domain */
    MB_FUNC_NAME(ifma_frommont52_p256_)(R.X, R.X);

    /* Store result */
    ifma_mb_to_HexStr(pa_shared_key, (const int64u(*)[MB_WIDTH])R.X, P256_BITSIZE);

    /* Clear computed shared keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])(&R), sizeof(R) / sizeof(U64));

    return status;
}

//----------------------------------------------
//      OpenSSL's specific implementations
//----------------------------------------------

#ifndef BN_OPENSSL_DISABLE

/*
// Internal (layer 2) DH function, ssl-specific API
// pa_shared_key    output computed shared secret
// pa_skey          input BIGNUMs with secret key value
// pa_pubx          input BIGNUMs with pub key x coordinate
// pa_puby          input BIGNUMs with pub key y coordinate
// pa_pubz          input BIGNUMs with pub key z coordinate
// pBuffer          input working buffer, currently unused
// use_jproj_coords input flag specifying the type of the pub key point
//
//      P = skey*W
*/
mbx_status MB_FUNC_NAME(internal_mbx_nistp256_ecdh_ssl_)(int8u* pa_shared_key[MB_WIDTH],
                                                         const BIGNUM* const pa_skey[MB_WIDTH],
                                                         const BIGNUM* const pa_pubx[MB_WIDTH],
                                                         const BIGNUM* const pa_puby[MB_WIDTH],
                                                         const BIGNUM* const pa_pubz[MB_WIDTH],
                                                         int8u* pBuffer,
                                                         int use_jproj_coords)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);

    mbx_status status = 0;

    /* Zero padded private keys in radix 2^64 */
    U64 secretz[P256_LEN64 + 1];
    ifma_BN_transpose_copy((int64u(*)[MB_WIDTH])secretz, (const BIGNUM**)pa_skey, P256_BITSIZE);
    secretz[P256_LEN64] = get_zero64();

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      is_zero(secretz, P256_LEN64 + 1),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* Сlear copy of the secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])secretz, sizeof(secretz) / sizeof(U64));
        return status;
    }

    /* Construct party's public point(P-> crypto_mb radix 2^52) */
    P256_POINT P;

    /* P-> radix 2^52 */
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])P.X, (const BIGNUM*(*))pa_pubx, P256_BITSIZE);
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])P.Y, (const BIGNUM*(*))pa_puby, P256_BITSIZE);
    if (use_jproj_coords)
        ifma_BN_to_mb((int64u(*)[MB_WIDTH])P.Z, (const BIGNUM*(*))pa_pubz, P256_BITSIZE);
    else
        MB_FUNC_NAME(mov_FE256_)(P.Z, (U64*)ones);

    /* Convert to Montgomery */
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.X, P.X);
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.Y, P.Y);
    MB_FUNC_NAME(ifma_tomont52_p256_)(P.Z, P.Z);

    /* Check if P does not belong to EC */
    __mb_mask not_on_curve_mask =
        not_mb_mask(MB_FUNC_NAME(ifma_is_on_curve_p256_)(&P, use_jproj_coords));
    /* Set points out of EC to infinity and update status*/
    MB_FUNC_NAME(mask_set_point_to_infinity_)(&P, not_on_curve_mask);
    status |= MBX_STS_BY_MASK_GENERIC(status, not_on_curve_mask, MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* Сlear copy of the secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])secretz, sizeof(secretz) / sizeof(U64));
        return status;
    }

    /* Сompute R = [secretz]*P */
    P256_POINT R;
    MB_FUNC_NAME(ifma_ec_nistp256_mul_point_)(&R, &P, secretz);

    /* Clear copy of the secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])secretz, sizeof(secretz) / sizeof(U64));

    /* Return affine R.x */
    __ALIGN64 U64 Z2[P256_LEN52];
    MB_FUNC_NAME(ifma_aminv52_p256_)(Z2, R.Z);    /* 1/Z   */
    MB_FUNC_NAME(ifma_ams52_p256_)(Z2, Z2);       /* 1/Z^2 */
    MB_FUNC_NAME(ifma_amm52_p256_)(R.X, R.X, Z2); /* x = (X) * (1/Z^2) */

    /* Move to regular domain */
    MB_FUNC_NAME(ifma_frommont52_p256_)(R.X, R.X);

    /* Store result */
    ifma_mb_to_HexStr(pa_shared_key, (const int64u(*)[MB_WIDTH])R.X, P256_BITSIZE);

    /* Clear computed shared keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])(&R), sizeof(R) / sizeof(U64));

    return status;
}

#endif /* BN_OPENSSL_DISABLE */

#endif /* #if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)) */
