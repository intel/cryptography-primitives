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
#include <internal/common/memory_clear.h>

#if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED))

#include <internal/common/ssl_convert_func.h>

/*
// Compute secret key inversion over n256
// skey         input secret key value
// inv_skey     output inversion (regular domain)
//
//      inv_skey = 1/skey(mod n256) == skey^(n256-2)(mod n256)
//
// Note: skey[] should be FE element of N256 based GF
*/
static void MB_FUNC_NAME(nistp256_ecdsa_inv_keys_)(U64 inv_skey[], const U64 skey[])
{
    MB_FUNC_NAME(ifma_tomont52_n256_)(inv_skey, skey);
    MB_FUNC_NAME(ifma_aminv52_n256_)(inv_skey, inv_skey); /* 1/skeys mod n256 */
    MB_FUNC_NAME(ifma_frommont52_n256_)(inv_skey, inv_skey);
}

/*
// Compute r-component of the ECDSA signature
// sign_r   output r-component of the signature (regular domain)
// skey     input secret key value
// 
//      r = ([skey]*G).x mod n256
//
// Note: skey[] should be transposed and zero expanded
*/
static __mb_mask MB_FUNC_NAME(nistp256_ecdsa_sign_r_)(U64 sign_r[], const U64 skey[])
{
    /* Compute ephemeral public key P */
    P256_POINT P;
    MB_FUNC_NAME(ifma_ec_nistp256_mul_pointbase_)(&P, skey);

    /* Convert projective->affine and extract affine P.x */
    MB_FUNC_NAME(ifma_aminv52_p256_)(P.Z, P.Z);    /* 1/Z   */
    MB_FUNC_NAME(ifma_ams52_p256_)(P.Z, P.Z);      /* 1/Z^2 */
    MB_FUNC_NAME(ifma_amm52_p256_)(P.X, P.X, P.Z); /* x = (X)*(1/Z^2) */

    /* Convert P.x to regular domain and then reduce by n256 */
    MB_FUNC_NAME(ifma_frommont52_p256_)(P.X, P.X);
    MB_FUNC_NAME(ifma_fastred52_pn256_)(sign_r, P.X); /* fast reduction p => n */

    return MB_FUNC_NAME(is_zero_FE256_)(sign_r);
}

/*
// Compute s-component of the ECDSA signature
// sign_s       output s-component of the signature (regular domain)
// msg          input message representation (regular domain)
// sign_r       input r-component of the signature (regular domain)
// inv_eph_skey input ephemeral secret key(nonce) (regular domain)
// reg_skey     input secret key value (regular domain)
//
//      s = (inv_eph) * (msg + prv_skey*sign_r) mod n256
*/
static __mb_mask MB_FUNC_NAME(nistp256_ecdsa_sign_s_)(U64 sign_s[],
                                                      U64 msg[],
                                                      const U64 sign_r[],
                                                      U64 inv_eph_skey[],
                                                      U64 reg_skey[])
{
    __ALIGN64 U64 tmp[P256_LEN52];

    /* Convert inputs to Montgomery over n256 domain */
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
// Internal (layer 2) sign set-up function
// pa_inv_eph_skey  output inversion of ephemeral key
// pa_sign_rp       output precomputed of r-component of the signature
// pa_eph_skey      input ephemeral key
// pBuffer          input working buffer, currently unused
//
//      r = ([eph_skey]*G).x mod n256
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_setup_)(
    int64u* pa_inv_eph_skey[MB_WIDTH],
    int64u* pa_sign_rp[MB_WIDTH],
    const int64u* const pa_eph_skey[MB_WIDTH],
    int8u* pBuffer)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);
    mbx_status status = 0;

    /* Convert keys into FE */
    U64 T[P256_LEN52];
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])T, pa_eph_skey, P256_BITSIZE);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(T),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* clear key's inversion */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])T, sizeof(T) / sizeof(U64));
        return status;
    }
    /* Compute inversion of ephemeral key */
    MB_FUNC_NAME(nistp256_ecdsa_inv_keys_)(T, T);
    /* Return results in suitable format */
    ifma_mb_to_BNU(pa_inv_eph_skey, (const int64u(*)[MB_WIDTH])T, P256_BITSIZE);

    /* Clear key's inversion */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])T, sizeof(T) / sizeof(U64));

    /* Convert keys into scalars */
    U64 scalarz[P256_LEN64 + 1];
    ifma_BNU_transpose_copy((int64u(*)[MB_WIDTH])scalarz, pa_eph_skey, P256_BITSIZE);
    scalarz[P256_LEN64] = get_zero64();

    /* Compute r-component of the DSA signature */
    __mb_mask stt_mask = MB_FUNC_NAME(nistp256_ecdsa_sign_r_)(T, scalarz);

    /* Clear copy of the ephemeral secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])scalarz, sizeof(scalarz) / sizeof(U64));

    /* Return results in suitable format */
    ifma_mb_to_BNU(pa_sign_rp, (const int64u(*)[MB_WIDTH])T, P256_BITSIZE);

    /* Check if sign_r != 0 */
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask, MBX_STATUS_SIGNATURE_ERR);

    return status;
}

/*
// Internal (layer 2) sign complete function
// pa_sign_r        output r-component of the signature
// pa_sign_s        output s-component of the signature
// pa_msg           input message representation
// pa_sign_rp       input precomputed of r-component of the signature
// pa_inv_eph_skey  input inversion of ephemeral key
// pa_reg_skey      input secret key value
// pBuffer          input working buffer, currently unused
//
//      s = (inv_eph) * (msg + reg_skey*sign_r) mod n256
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_complete_)(
    int8u* pa_sign_r[MB_WIDTH],
    int8u* pa_sign_s[MB_WIDTH],
    const int8u* const pa_msg[MB_WIDTH],
    const int64u* const pa_sign_rp[MB_WIDTH],
    const int64u* const pa_inv_eph_skey[MB_WIDTH],
    const int64u* const pa_reg_skey[MB_WIDTH],
    int8u* pBuffer)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);

    mbx_status status = 0;

    __ALIGN64 U64 inv_eph[P256_LEN52];
    __ALIGN64 U64 reg_skey[P256_LEN52];
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];
    __ALIGN64 U64 msg[P256_LEN52];

    /* Convert inv_eph, reg_skey, sign_r and message to mb format */
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])inv_eph, pa_inv_eph_skey, P256_BITSIZE);
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])reg_skey, pa_reg_skey, P256_BITSIZE);
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])sign_r, pa_sign_rp, P256_BITSIZE);
    ifma_HexStr_to_mb((int64u(*)[MB_WIDTH])msg, pa_msg, P256_BITSIZE);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(inv_eph),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(reg_skey),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(sign_r),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(msg),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* Clear copy of the ephemeral secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])inv_eph, sizeof(inv_eph) / sizeof(U64));
        /* Clear copy of the regular secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])reg_skey, sizeof(reg_skey) / sizeof(U64));
        return status;
    }

    /* Compute s- signature component: s = (inv_eph) * (msg + prv_skey*sign_r) mod n256 */
    __mb_mask stt_mask_s =
        MB_FUNC_NAME(nistp256_ecdsa_sign_s_)(sign_s, msg, sign_r, inv_eph, reg_skey);

    /* Clear copy of the ephemeral and regular secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])inv_eph, sizeof(inv_eph) / sizeof(U64));
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])reg_skey, sizeof(reg_skey) / sizeof(U64));

    /* Convert sign_r and sing_s to strings */
    ifma_mb_to_HexStr(pa_sign_r, (const int64u(*)[MB_WIDTH])sign_r, P256_BITSIZE);
    ifma_mb_to_HexStr(pa_sign_s, (const int64u(*)[MB_WIDTH])sign_s, P256_BITSIZE);

    /* Check if sign_r != 0 */
    __mb_mask stt_mask_r = MB_FUNC_NAME(is_zero_FE256_)(sign_r);
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask_r, MBX_STATUS_SIGNATURE_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask_s, MBX_STATUS_SIGNATURE_ERR);

    return status;
}

/*
// Internal (layer 2) sign function
// pa_sign_r        output r-component of the signature
// pa_sign_s        output s-component of the signature
// pa_msg           input message representation
// pa_eph_skey      input ephemeral key
// pa_reg_skey      input secret key value
// pBuffer          input working buffer, currently unused
//
//      r = ([eph_skey]*G).x mod n256
//      s = (inv_eph) * (msg + reg_skey*sign_r) mod n256
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_)(int8u* pa_sign_r[MB_WIDTH],
                                                       int8u* pa_sign_s[MB_WIDTH],
                                                       const int8u* const pa_msg[MB_WIDTH],
                                                       const int64u* const pa_eph_skey[MB_WIDTH],
                                                       const int64u* const pa_reg_skey[MB_WIDTH],
                                                       int8u* pBuffer)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);

    mbx_status status = 0;

    __ALIGN64 U64 inv_eph_key[P256_LEN52];
    __ALIGN64 U64 scalar[P256_LEN64 + 1];
    __ALIGN64 U64 reg_key[P256_LEN52];
    __ALIGN64 U64 msg[P256_LEN52];

    /* Output signature */
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];

    /* Convert ephemeral and reg_skey keys into radix 2^52 mb field elements(FE) */
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])inv_eph_key, pa_eph_skey, P256_BITSIZE);
    ifma_BNU_to_mb((int64u(*)[MB_WIDTH])reg_key, pa_reg_skey, P256_BITSIZE);
    /* Convert ephemeral keys into scalar mb, without radix conversion */
    ifma_BNU_transpose_copy((int64u(*)[MB_WIDTH])scalar, pa_eph_skey, P256_BITSIZE);
    scalar[P256_LEN64] = get_zero64();
    /* Convert message into radix 2^52 */
    ifma_HexStr_to_mb((int64u(*)[MB_WIDTH])msg, pa_msg, P256_BITSIZE);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(inv_eph_key),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(reg_key),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(msg),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* Clear copy of the ephemeral and regular secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])inv_eph_key, sizeof(inv_eph_key) / sizeof(U64));
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])scalar, sizeof(scalar) / sizeof(U64));
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])reg_key, sizeof(reg_key) / sizeof(U64));
        return status;
    }

    /* Compute inversion k^-1 */
    MB_FUNC_NAME(nistp256_ecdsa_inv_keys_)(inv_eph_key, inv_eph_key);

    /* Compute r-component */
    __mb_mask stt_mask_r = MB_FUNC_NAME(nistp256_ecdsa_sign_r_)(sign_r, scalar);
    /* Compute s-component */
    __mb_mask stt_mask_s =
        MB_FUNC_NAME(nistp256_ecdsa_sign_s_)(sign_s, msg, sign_r, inv_eph_key, reg_key);

    /* Clear copy of the ephemeral and regular secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])inv_eph_key, sizeof(inv_eph_key) / sizeof(U64));
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])scalar, sizeof(scalar) / sizeof(U64));
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])reg_key, sizeof(reg_key) / sizeof(U64));

    /* Convert signature components to strings */
    ifma_mb_to_HexStr(pa_sign_r, (const int64u(*)[MB_WIDTH])sign_r, P256_BITSIZE);
    ifma_mb_to_HexStr(pa_sign_s, (const int64u(*)[MB_WIDTH])sign_s, P256_BITSIZE);

    /* Check if sign_r != 0 and sign_s != 0 */
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask_r, MBX_STATUS_SIGNATURE_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask_s, MBX_STATUS_SIGNATURE_ERR);

    return status;
}

//----------------------------------------------
//      OpenSSL's specific implementations
//----------------------------------------------

#ifndef BN_OPENSSL_DISABLE

/*
// Internal (layer 2) sign set-up function, ssl-specific API
// pa_inv_skey      output BIGNUMs with inversion of ephemeral key
// pa_sign_rp       output BIGNUMs with precomputed of r-component of the signature
// pa_eph_skey      input BIGNUMs with ephemeral key
// pBuffer          input working buffer, currently unused
//
//      r = ([eph_skey]*G).x mod n256
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_setup_ssl_)(
    BIGNUM* pa_inv_skey[MB_WIDTH],
    BIGNUM* pa_sign_rp[MB_WIDTH],
    const BIGNUM* const pa_eph_skey[MB_WIDTH],
    int8u* pBuffer)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);

    mbx_status status = 0;

    /* Convert keys into FE */
    U64 T[P256_LEN52];
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])T, pa_eph_skey, P256_BITSIZE);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(T),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* Clear key's inversion */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])T, sizeof(T) / sizeof(U64));
        return status;
    }
    /* Compute inversion of ephemeral key */
    MB_FUNC_NAME(nistp256_ecdsa_inv_keys_)(T, T);
    /* Return results in suitable format */
    MB_FUNC_NAME(ifma_to_BN_)(pa_inv_skey, (const int64u(*)[MB_WIDTH])T, P256_BITSIZE);

    /* Clear key's inversion */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])T, sizeof(T) / sizeof(U64));

    /* Convert keys into scalars */
    U64 scalarz[P256_LEN64 + 1];
    ifma_BN_transpose_copy((int64u(*)[MB_WIDTH])scalarz, pa_eph_skey, P256_BITSIZE);
    scalarz[P256_LEN64] = get_zero64();

    /* Compute r-component of the DSA signature */
    __mb_mask stt_mask = MB_FUNC_NAME(nistp256_ecdsa_sign_r_)(T, scalarz);

    /* Clear copy of the ephemeral secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])scalarz, sizeof(scalarz) / sizeof(U64));

    /* Return results in suitable format */
    MB_FUNC_NAME(ifma_to_BN_)(pa_sign_rp, (const int64u(*)[MB_WIDTH])T, P256_BITSIZE);

    /* Check if sign_r != 0 */
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask, MBX_STATUS_SIGNATURE_ERR);

    return status;
}

/*
// Internal (layer 2) sign complete function, ssl-specific API
// pa_sign_r        output r-component of the signature
// pa_sign_s        output s-component of the signature
// pa_msg           input message representation
// pa_sign_rp       input BIGNUMs with precomputed of r-component of the signature
// pa_inv_eph_skey  input BIGNUMs with inversion of ephemeral key
// pa_reg_skey      input BIGNUMs with secret key value
// pBuffer          input working buffer, currently unused
//
//      s = (inv_eph) * (msg + reg_skey*sign_r) mod n256
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_complete_ssl_)(
    int8u* pa_sign_r[MB_WIDTH],
    int8u* pa_sign_s[MB_WIDTH],
    const int8u* const pa_msg[MB_WIDTH],
    const BIGNUM* const pa_sign_rp[MB_WIDTH],
    const BIGNUM* const pa_inv_eph_skey[MB_WIDTH],
    const BIGNUM* const pa_reg_skey[MB_WIDTH],
    int8u* pBuffer)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);

    mbx_status status = 0;

    __ALIGN64 U64 inv_eph[P256_LEN52];
    __ALIGN64 U64 reg_skey[P256_LEN52];
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];
    __ALIGN64 U64 msg[P256_LEN52];

    /* Convert inv_eph, reg_skey, sign_r and message to mb format */
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])inv_eph, pa_inv_eph_skey, P256_BITSIZE);
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])reg_skey, pa_reg_skey, P256_BITSIZE);
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])sign_r, pa_sign_rp, P256_BITSIZE);
    ifma_HexStr_to_mb((int64u(*)[MB_WIDTH])msg, pa_msg, P256_BITSIZE);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(inv_eph),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(reg_skey),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(sign_r),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(msg),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* Clear copy of the ephemeral secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])inv_eph, sizeof(inv_eph) / sizeof(U64));
        /* Clear copy of the regular secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])reg_skey, sizeof(reg_skey) / sizeof(U64));
        return status;
    }

    /* Compute s- signature component: s = (inv_eph) * (msg + prv_skey*sign_r) mod n256 */
    __mb_mask stt_mask_s =
        MB_FUNC_NAME(nistp256_ecdsa_sign_s_)(sign_s, msg, sign_r, inv_eph, reg_skey);

    /* Clear copy of the ephemeral and regular secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])inv_eph, sizeof(inv_eph) / sizeof(U64));
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])reg_skey, sizeof(reg_skey) / sizeof(U64));

    /* Convert sign_r and sing_s to strings */
    ifma_mb_to_HexStr(pa_sign_r, (const int64u(*)[MB_WIDTH])sign_r, P256_BITSIZE);
    ifma_mb_to_HexStr(pa_sign_s, (const int64u(*)[MB_WIDTH])sign_s, P256_BITSIZE);

    /* Check if sign_r != 0 */
    __mb_mask stt_mask_r = MB_FUNC_NAME(is_zero_FE256_)(sign_r);
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask_r, MBX_STATUS_SIGNATURE_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask_s, MBX_STATUS_SIGNATURE_ERR);

    return status;
}

/*
// Internal (layer 2) sign function, ssl-specific API
// pa_sign_r        output r-component of the signature
// pa_sign_s        output s-component of the signature
// pa_msg           input message representation
// pa_eph_skey      input BIGNUMs with ephemeral key
// pa_reg_skey      input BIGNUMs with secret key value
// pBuffer          input working buffer, currently unused
//
//      r = ([eph_skey]*G).x mod n256
//      s = (inv_eph) * (msg + reg_skey*sign_r) mod n256
*/
mbx_status MB_FUNC_NAME(internal_nistp256_ecdsa_sign_ssl_)(
    int8u* pa_sign_r[MB_WIDTH],
    int8u* pa_sign_s[MB_WIDTH],
    const int8u* const pa_msg[MB_WIDTH],
    const BIGNUM* const pa_eph_skey[MB_WIDTH],
    const BIGNUM* const pa_reg_skey[MB_WIDTH],
    int8u* pBuffer)
{
    MBX_UNREFERENCED_PARAMETER(pBuffer);

    mbx_status status = 0;

    __ALIGN64 U64 inv_eph_key[P256_LEN52];
    __ALIGN64 U64 scalar[P256_LEN64 + 1];
    __ALIGN64 U64 reg_key[P256_LEN52];
    __ALIGN64 U64 msg[P256_LEN52];

    /* Output signature */
    __ALIGN64 U64 sign_r[P256_LEN52];
    __ALIGN64 U64 sign_s[P256_LEN52];

    /* Convert ephemeral and reg_skey keys into radix 2^52 mb field elements(FE) */
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])inv_eph_key, pa_eph_skey, P256_BITSIZE);
    ifma_BN_to_mb((int64u(*)[MB_WIDTH])reg_key, pa_reg_skey, P256_BITSIZE);
    /* Convert ephemeral keys into scalar mb, without radix conversion */
    ifma_BN_transpose_copy((int64u(*)[MB_WIDTH])scalar, pa_eph_skey, P256_BITSIZE);
    scalar[P256_LEN64] = get_zero64();
    /* Convert message into radix 2^52 */
    ifma_HexStr_to_mb((int64u(*)[MB_WIDTH])msg, pa_msg, P256_BITSIZE);

    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(inv_eph_key),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(is_zero_FE256_)(reg_key),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status,
                                      MB_FUNC_NAME(ifma_check_range_n256_)(msg),
                                      MBX_STATUS_MISMATCH_PARAM_ERR);

    if (!MBX_IS_ANY_OK_STS(status)) {
        /* Clear copy of the ephemeral and regular secret keys */
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])inv_eph_key, sizeof(inv_eph_key) / sizeof(U64));
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])scalar, sizeof(scalar) / sizeof(U64));
        MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])reg_key, sizeof(reg_key) / sizeof(U64));
        return status;
    }

    /* Compute inversion k^-1 */
    MB_FUNC_NAME(nistp256_ecdsa_inv_keys_)(inv_eph_key, inv_eph_key);

    /* Compute r-component */
    __mb_mask stt_mask_r = MB_FUNC_NAME(nistp256_ecdsa_sign_r_)(sign_r, scalar);
    /* Compute s-component */
    __mb_mask stt_mask_s =
        MB_FUNC_NAME(nistp256_ecdsa_sign_s_)(sign_s, msg, sign_r, inv_eph_key, reg_key);

    /* Clear copy of the ephemeral and regular secret keys */
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])inv_eph_key, sizeof(inv_eph_key) / sizeof(U64));
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])scalar, sizeof(scalar) / sizeof(U64));
    MB_FUNC_NAME(zero_)((int64u(*)[MB_WIDTH])reg_key, sizeof(reg_key) / sizeof(U64));

    /* Convert signature components to strings */
    ifma_mb_to_HexStr(pa_sign_r, (const int64u(*)[MB_WIDTH])sign_r, P256_BITSIZE);
    ifma_mb_to_HexStr(pa_sign_s, (const int64u(*)[MB_WIDTH])sign_s, P256_BITSIZE);

    /* Check if sign_r != 0 and sign_s != 0 */
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask_r, MBX_STATUS_SIGNATURE_ERR);
    status |= MBX_STS_BY_MASK_GENERIC(status, stt_mask_s, MBX_STATUS_SIGNATURE_ERR);

    return status;
}

#endif /* BN_OPENSSL_DISABLE */

#endif /* #if ((_MBX >= _MBX_K1) || ((_MBX >= _MBX_L9) && _MBX_AVX_IFMA_SUPPORTED)) */
