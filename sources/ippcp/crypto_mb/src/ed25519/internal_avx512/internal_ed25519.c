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
#include <internal/common/ifma_math.h>
#include <internal/common/ifma_cvt52.h>
#include <internal/rsa/ifma_rsa_arith.h>

#include <crypto_mb/ed25519.h>
#include <internal/ed25519/ifma_arith_ed25519.h>
#include <internal/ed25519/ifma_arith_p25519.h>
#include <internal/ed25519/ifma_arith_n25519.h>
#include <internal/ed25519/sha512.h>

#if (_MBX >= _MBX_K1)

/* length of SHA512 hash in bits and bytes */
#define SHA512_HASH_BITLENGTH (512)
#define HASH_LENGTH           NUMBER_OF_DIGITS(SHA512_HASH_BITLENGTH, 8)

void ed25519_expand_key(int8u* pa_secret_expand[8],
                        const ed25519_private_key* const pa_secret_key[8])
{
    /* do hash of secret keys in sequence */
    for (int n = 0; n < 8; n++) {
        const ed25519_private_key* psecret = pa_secret_key[n];
        if (psecret) {
            SHA512MsgDigest(*psecret, sizeof(ed25519_private_key), pa_secret_expand[n]);
            /* prune the buffer according to RFC8032 */
            pa_secret_expand[n][0] &= 0xf8;
            pa_secret_expand[n][31] &= 0x7f;
            pa_secret_expand[n][31] |= 0x40;
        }
    }
}

mbx_status internal_avx512_ed25519_public_key_mb8(
    ed25519_public_key* pa_public_key[8],
    const ed25519_private_key* const pa_private_key[8])
{
    mbx_status status = 0;
    /* continue processing if there are correct parameters */
    if (MBX_IS_ANY_OK_STS(status)) {

        int8u sha512_digest[8][HASH_LENGTH] = { 0 };
        int64u* pa_sha512_digest[] = { (int64u*)sha512_digest[0], (int64u*)sha512_digest[1],
                                       (int64u*)sha512_digest[2], (int64u*)sha512_digest[3],
                                       (int64u*)sha512_digest[4], (int64u*)sha512_digest[5],
                                       (int64u*)sha512_digest[6], (int64u*)sha512_digest[7] };
        /* expand secret keys */
        ed25519_expand_key((int8u**)pa_sha512_digest, pa_private_key);

        /* convert into mb format */
        U64 scalar[FE_LEN64];
        ifma_BNU_transpose_copy(
            (int64u(*)[8])scalar, (const int64u**)pa_sha512_digest, SHA512_HASH_BITLENGTH / 2);

        /* r = [scalar]*G */
        ge52_ext_mb r;
        ifma_ed25519_mul_basepoint(&r, scalar);

        /* compress point to public */
        fe52_mb packed_point;
        ge52_ext_compress(packed_point, &r);

        /* return result */
        ifma_mb8_to_BNU(
            (int64u* const*)pa_public_key, (const int64u(*)[8])packed_point, GE25519_COMP_BITSIZE);

        /* clear memory containing potentially secret data */
        MB_FUNC_NAME(zero_)((int64u(*)[8])scalar, sizeof(scalar) / sizeof(U64));
        MB_FUNC_NAME(zero_)((int64u(*)[8])sha512_digest, sizeof(sha512_digest) / sizeof(U64));
    }
    return status;
}


/*
// Computes ED2519 signature
// pa_sign_r[]       array of pointers to the computed r-components of the signatures
// pa_sign_s[]       array of pointers to the computed s-components of the signatures
// pa_msg[]          array of pointers to the messages are being signed
// msgLen[]          array of messages lengths (in bytes)
// pa_private_key[]  array of pointers to the signer's private keys
// pa_public_key[]   array of pointers to the signer's public keys
*/
static void ed25519_nonce(int8u* pa_nonce[8],
                          int8u* pa_az[8],
                          const int8u* const pa_msg[8],
                          const int32u msgLen[8])
{
    SHA512State pState;

    for (int n = 0; n < 8; n++) {
        int8u* az        = pa_az[n] + HASH_LENGTH / 2;
        const int8u* msg = pa_msg[n];
        int32u mlen      = msgLen[n];

        SHA512Init(&pState);
        SHA512Update(az, 32, &pState);
        if (msg)
            SHA512Update(msg, mlen, &pState);

        SHA512Final(pa_nonce[n], &pState);
    }
}

static void ed25519_hash_r_pub_msg(int8u* pa_hram[8],
                                   const ed25519_sign_component* const pa_sign_r[],
                                   const ed25519_public_key* const pa_public_key[8],
                                   const int8u* const pa_msg[8],
                                   const int32u msgLen[8])
{
    SHA512State pState;

    for (int n = 0; n < 8; n++) {
        const ed25519_sign_component* sign_r = pa_sign_r[n];
        const ed25519_public_key* public     = pa_public_key[n];
        const int8u* msg                     = pa_msg[n];
        int32u mlen                          = msgLen[n];
        SHA512Init(&pState);

        if (sign_r)
            SHA512Update((const int8u*)sign_r, NUMBER_OF_DIGITS(GE25519_COMP_BITSIZE, 8), &pState);
        if (public)
            SHA512Update((const int8u*)public, sizeof(ed25519_public_key), &pState);
        if (msg)
            SHA512Update(msg, mlen, &pState);
        SHA512Final(pa_hram[n], &pState);
    }
}

mbx_status MB_FUNC_NAME(internal_avx512_ed25519_sign_)(
    ed25519_sign_component* pa_sign_r[8],
    ed25519_sign_component* pa_sign_s[8],
    const int8u* const pa_msg[8],
    const int32u msgLen[8],
    const ed25519_private_key* const pa_private_key[8],
    const ed25519_public_key* const pa_public_key[8])
{
    mbx_status status = 0;
    /* continue processing if there are correct parameters */
    if (MBX_IS_ANY_OK_STS(status)) {
        //#define HASH_LENGTH    NUMBER_OF_DIGITS(SHA512_DIGEST_BITLENGTH, 8)

        /* expanded secret keys */
        int8u az[8][HASH_LENGTH] = { 0 };
        int64u* pa_az[8]         = { (int64u*)az[0], (int64u*)az[1], (int64u*)az[2], (int64u*)az[3],
                                     (int64u*)az[4], (int64u*)az[5], (int64u*)az[6], (int64u*)az[7] };

        /* nonce */
        int8u nonce[8][HASH_LENGTH] = { 0 };
        int64u* pa_nonce[8]         = { (int64u*)nonce[0], (int64u*)nonce[1], (int64u*)nonce[2],
                                        (int64u*)nonce[3], (int64u*)nonce[4], (int64u*)nonce[5],
                                        (int64u*)nonce[6], (int64u*)nonce[7] };

        /* hram */
        int8u hram[8][HASH_LENGTH] = { 0 };
        int64u* pa_hram[8]         = { (int64u*)hram[0], (int64u*)hram[1], (int64u*)hram[2],
                                       (int64u*)hram[3], (int64u*)hram[4], (int64u*)hram[5],
                                       (int64u*)hram[6], (int64u*)hram[7] };

        /* expands secret key,  az = H(private_key) */
        ed25519_expand_key((int8u**)pa_az, pa_private_key);
        U64 mb_az[FE_LEN52];
        ifma_BNU_to_mb8((int64u(*)[8])mb_az, (const int64u**)pa_az, SHA512_HASH_BITLENGTH / 2);

        /* computes nonce, nonce = H(az+32, msg)  */
        /* Note: only a second half of each pa_az[n] item is used in the ed25519_nonce() function */
        ed25519_nonce((int8u**)pa_nonce, (int8u**)pa_az, pa_msg, msgLen);

        /* reduce nonce wrt n */
        U64 mb_nonce[NUMBER_OF_DIGITS(SHA512_HASH_BITLENGTH, DIGIT_SIZE)];
        ifma_BNU_to_mb8((int64u(*)[8])mb_nonce, (const int64u**)pa_nonce, SHA512_HASH_BITLENGTH);
        ifma52_ed25519n_reduce(mb_nonce, mb_nonce);

        /* computes r-component of the signature */
        ifma_mb8_to_BNU(pa_nonce, (const int64u(*)[8])mb_nonce, N25519_BITSIZE);
        fe52_mb mb_scalar;
        ifma_BNU_transpose_copy((int64u(*)[8])mb_scalar, (const int64u**)pa_nonce, N25519_BITSIZE);

        ge52_ext_mb R;
        ifma_ed25519_mul_basepoint(&R, mb_scalar); /* R = [scalar]*G */
        fe52_mb mb_sign_r;
        ge52_ext_compress(mb_sign_r, &R);          /* compress point to r-component */

        /* store r-component of the  signature */
        ifma_mb8_to_BNU(
            (int64u* const*)pa_sign_r, (const int64u(*)[8])mb_sign_r, GE25519_COMP_BITSIZE);

        /* computes hram, hram = H(r_sign, public_key,  msg)  */
        ed25519_hash_r_pub_msg((int8u**)pa_hram,
                               (const ed25519_sign_component**)pa_sign_r,
                               pa_public_key,
                               pa_msg,
                               msgLen);

        U64 mb_hram[NUMBER_OF_DIGITS(SHA512_HASH_BITLENGTH, DIGIT_SIZE)];
        ifma_BNU_to_mb8((int64u(*)[8])mb_hram, (const int64u**)pa_hram, SHA512_HASH_BITLENGTH);
        ifma52_ed25519n_reduce(mb_hram, mb_hram);

        /* s = hram*az + nonce */
        fe52_mb mb_sign_s;
        ifma52_ed25519n_madd(mb_sign_s, mb_hram, mb_az, mb_nonce);

        /* store s-component of the signature */
        ifma_mb8_to_BNU((int64u* const*)pa_sign_s, (const int64u(*)[8])mb_sign_s, N25519_BITSIZE);

        /* clear memory containing potentially secret data */
        MB_FUNC_NAME(zero_)((int64u(*)[8])az, sizeof(az) / sizeof(U64));
        MB_FUNC_NAME(zero_)((int64u(*)[8])nonce, sizeof(nonce) / sizeof(U64));
        MB_FUNC_NAME(zero_)((int64u(*)[8])mb_scalar, sizeof(mb_scalar) / sizeof(U64));
    }

    return status;
}

/*
// ED25519 prime base point order
// n = 2^252+27742317777372353535851937790883648493 = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
// in 2^64 radix
*/
__ALIGN64 static int64u ed25519n_mb64[NE_LEN64][sizeof(U64) / sizeof(int64u)] = {
    { REP8_DECL(0x5812631A5CF5D3ED) },
    { REP8_DECL(0x14DEF9DEA2F79CD6) },
    { REP8_DECL(0x0000000000000000) },
    { REP8_DECL(0x1000000000000000) }
};

mbx_status MB_FUNC_NAME(internal_avx512_ed25519_verify_)(
    const ed25519_sign_component* const pa_sign_r[8],
    const ed25519_sign_component* const pa_sign_s[8],
    const int8u* const pa_msg[8],
    const int32u msgLen[8],
    const ed25519_public_key* const pa_public_key[8])
{
    mbx_status status = 0;
    /* continue processing if there are correct parameters */
    if (MBX_IS_ANY_OK_STS(status)) {

        /* h = SHA512(sign_r || public_key || msg) */
        __ALIGN64 int8u h[8][HASH_LENGTH] = { 0 };
        int64u* pa_h[8] = { (int64u*)h[0], (int64u*)h[1], (int64u*)h[2], (int64u*)h[3],
                            (int64u*)h[4], (int64u*)h[5], (int64u*)h[6], (int64u*)h[7] };
        ed25519_hash_r_pub_msg((int8u**)pa_h, pa_sign_r, pa_public_key, pa_msg, msgLen);

        /* reduce h %= n */
        __ALIGN64 U64 h_mb[NUMBER_OF_DIGITS(SHA512_HASH_BITLENGTH, DIGIT_SIZE)];
        ifma_BNU_to_mb8((int64u(*)[8])h_mb, (const int64u**)pa_h, SHA512_HASH_BITLENGTH);
        ifma52_ed25519n_reduce(h_mb, h_mb);

        /* convert h_mb: fe52 => fe64 */
        __ALIGN64 U64 h64_mb[FE_LEN64 + 1];
        fe52_to_fe64_mb(h64_mb, h_mb);
        h64_mb[FE_LEN64] = get_zero64();

        /* input r-components to mb */
        __ALIGN64 fe52_mb inputR_mb;
        ifma_BNU_to_mb8((int64u(*)[8])inputR_mb, (const int64u**)pa_sign_r, GE25519_COMP_BITSIZE);

        /* input s-components to mb */
        __ALIGN64 U64 s_mb[NE_LEN64 + 1];
        ifma_BNU_transpose_copy((int64u(*)[8])s_mb, (const int64u**)pa_sign_s, 256);
        s_mb[NE_LEN64] = get_zero64();

        /* (comppressed) publickey to mb */
        __ALIGN64 fe52_mb pubfe_mb;
        ifma_BNU_to_mb8((int64u(*)[8])pubfe_mb, (const int64u**)pa_public_key, P25519_BITSIZE + 1);

        /* check that s<n */
        U64* n_mb  = (U64*)ed25519n_mb64;
        __mmask8 k = 0;
        for (int n = NE_LEN64; n > 0; n--) {
            k |= cmp64_mask(n_mb[n - 1], s_mb[n - 1], _MM_CMPINT_NLE);
        }
        status |= MBX_SET_STS_BY_MASK(status, ~k, MBX_STATUS_MISMATCH_PARAM_ERR);

        /* continue processing if there are correct parameters */
        if (MBX_IS_ANY_OK_STS(status)) {
            /* decompress public to ext point A */
            __ALIGN64 ge52_ext_mb pubA_mb;
            k = ge52_ext_decompress(&pubA_mb, pubfe_mb);
            fe52_neg(pubA_mb.X, pubA_mb.X);
            fe52_neg(pubA_mb.T, pubA_mb.T);
            status |= MBX_SET_STS_BY_MASK(status, ~k, MBX_STATUS_SIGNATURE_ERR);

            if (MBX_IS_ANY_OK_STS(status)) {
                /* R = [h]A + [s]G */
                __ALIGN64 ge52_ext_mb R_mb;
                ifma_ed25519_prod_point(&R_mb, &pubA_mb, h64_mb, s_mb);

                /* recovered r-components */
                __ALIGN64 fe52_mb checkR_mb;
                ge52_ext_compress(checkR_mb, &R_mb);

                /* check that recovered r- and input r- components are equal each other */
                k = fe52_mb_is_equ(checkR_mb, inputR_mb);
                status |= MBX_SET_STS_BY_MASK(status, ~k, MBX_STATUS_SIGNATURE_ERR);
            }
        }
    }
    return status;
}

#endif /* #if (_MBX>=_MBX_K1) */
