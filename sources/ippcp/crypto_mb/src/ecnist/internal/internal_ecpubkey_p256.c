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
#include <internal/common/memory_clear.h>

#if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED))

/*
// Internal (layer 2) public key generation function
// pa_pubx          output pub key x coordinate
// pa_puby          output pub key y coordinate
// pa_pubz          output pub key z coordinate
// pa_skey          input secret key value
// pBuffer          input working buffer
// use_jproj_coords input flag specifying the type of the pub key point
//
//      P = skey*G
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecpublic_key_)(int64u* pa_pubx[MB_WIDTH],
                                                         int64u* pa_puby[MB_WIDTH],
                                                         int64u* pa_pubz[MB_WIDTH],
                                                         const int64u* const pa_skey[MB_WIDTH],
                                                         int8u* pBuffer,
                                                         int use_jproj_coords)
{
    mbx_status status = 0;

    /* Zero padded keys in radix 2^64 */
    U64 scalarz[P256_LEN64 + 1];
    ifma_BNU_transpose_copy((int64u(*)[MB_WIDTH])scalarz, pa_skey, P256_BITSIZE);
    scalarz[P256_LEN64] = get_zero64();

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      is_zero(scalarz, P256_LEN64 + 1),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    /* Do not need to clear copy of secret keys before this return - all of them is NULL or zero */
    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    /* Public key */
    P256_POINT P;

    /* Compute public keys */
    MB_FUNC_NAME(ifma_ec_nistp256_mul_pointbase_)(&P, scalarz);
    /* Clear copy of the secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])scalarz, sizeof(scalarz) / sizeof(U64));

    if (!use_jproj_coords)
        MB_FUNC_NAME(get_nistp256_ec_affine_coords_)(P.X, P.Y, &P);

    /* Convert P coordinates to regular domain */
    MB_FUNC_NAME(ifma_frommont52_p256_)(P.X, P.X);
    MB_FUNC_NAME(ifma_frommont52_p256_)(P.Y, P.Y);
    if (use_jproj_coords)
        MB_FUNC_NAME(ifma_frommont52_p256_)(P.Z, P.Z);

    /* Store result */
    ifma_mb_to_BNU(pa_pubx, (const int64u(*)[MB_WIDTH])P.X, P256_BITSIZE);
    ifma_mb_to_BNU(pa_puby, (const int64u(*)[MB_WIDTH])P.Y, P256_BITSIZE);
    if (use_jproj_coords)
        ifma_mb_to_BNU(pa_pubz, (const int64u(*)[MB_WIDTH])P.Z, P256_BITSIZE);

    return status;
}

//----------------------------------------------
//      OpenSSL's specific implementations
//----------------------------------------------

#ifndef BN_OPENSSL_DISABLE

/*
// Internal (layer 2) public key generation function, ssl-specific API
// pa_pubx          output BIGNUMs with pub key x coordinate
// pa_puby          output BIGNUMs with pub key y coordinate
// pa_pubz          output BIGNUMs with pub key z coordinate
// pa_skey          input BIGNUMs with secret key value
// pBuffer          input working buffer
// use_jproj_coords input flag specifying the type of the pub key point
//
//      P = skey*G
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecpublic_key_ssl_)(BIGNUM* pa_pubx[MB_WIDTH],
                                                             BIGNUM* pa_puby[MB_WIDTH],
                                                             BIGNUM* pa_pubz[MB_WIDTH],
                                                             const BIGNUM* const pa_skey[MB_WIDTH],
                                                             int8u* pBuffer,
                                                             int use_jproj_coords)
{
    mbx_status status = 0;
    int buf_no        = 0;

    /* Zero padded keys in radix 2^64 */
    U64 scalarz[P256_LEN64 + 1];
    ifma_BN_transpose_copy((int64u(*)[MB_WIDTH])scalarz, pa_skey, P256_BITSIZE);
    scalarz[P256_LEN64] = get_zero64();

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      is_zero(scalarz, P256_LEN64 + 1),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    /* Do not need to clear copy of secret keys before this return - all of them is NULL or zero */
    if (!MBX_IS_ANY_OK_STS(status))
        return status;

    /* Public key */
    P256_POINT P;

    /* Compute public keys */
    MB_FUNC_NAME(ifma_ec_nistp256_mul_pointbase_)(&P, scalarz);
    /* Clear copy of the secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])scalarz, sizeof(scalarz) / sizeof(U64));

    if (!use_jproj_coords)
        MB_FUNC_NAME(get_nistp256_ec_affine_coords_)(P.X, P.Y, &P);

    /* Convert P coordinates to regular domain */
    MB_FUNC_NAME(ifma_frommont52_p256_)(P.X, P.X);
    MB_FUNC_NAME(ifma_frommont52_p256_)(P.Y, P.Y);
    if (use_jproj_coords)
        MB_FUNC_NAME(ifma_frommont52_p256_)(P.Z, P.Z);

    /* Convert public key and store result in output BIGNUMs */
    int8u tmp[MB_WIDTH][NUMBER_OF_DIGITS(P256_BITSIZE, 8)];
    int8u* pa_tmp[MB_WIDTH];
    for (int32u idx = 0; idx < MB_WIDTH; idx++)
        pa_tmp[idx] = tmp[idx];

    /* X */
    ifma_mb_to_HexStr(pa_tmp, (const int64u(*)[MB_WIDTH])P.X, P256_BITSIZE);
    for (buf_no = 0; (buf_no < MB_WIDTH) && (0 == MBX_GET_STS(status, buf_no)); buf_no++) {
        BN_bin2bn(pa_tmp[buf_no], NUMBER_OF_DIGITS(P256_BITSIZE, 8), pa_pubx[buf_no]);
    }

    /* Y */
    ifma_mb_to_HexStr(pa_tmp, (const int64u(*)[MB_WIDTH])P.Y, P256_BITSIZE);
    for (buf_no = 0; (buf_no < MB_WIDTH) && (0 == MBX_GET_STS(status, buf_no)); buf_no++) {
        BN_bin2bn(pa_tmp[buf_no], NUMBER_OF_DIGITS(P256_BITSIZE, 8), pa_puby[buf_no]);
    }

    /* Z */
    if (use_jproj_coords) {
        ifma_mb_to_HexStr(pa_tmp, (const int64u(*)[MB_WIDTH])P.Z, P256_BITSIZE);
        for (buf_no = 0; (buf_no < MB_WIDTH) && (0 == MBX_GET_STS(status, buf_no)); buf_no++) {
            BN_bin2bn(pa_tmp[buf_no], NUMBER_OF_DIGITS(P256_BITSIZE, 8), pa_pubz[buf_no]);
        }
    }

    return status;
}

#endif /* BN_OPENSSL_DISABLE */

#endif /* #if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)) */
