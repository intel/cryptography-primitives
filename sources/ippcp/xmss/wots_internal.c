/*************************************************************************
* Copyright (C) 2023 Intel Corporation
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

#include "owndefs.h"
#include "owncp.h"
#include "pcpbnumisc.h"
#include "pcpprng.h"
#include "xmss_internal/wots.h"

/*
 * A byte string can be considered as a string of base w numbers, i.e.,
 * integers in the set {0, ... , w - 1}. The correspondence is defined
 * by the function base_w as follows. If X
 * is a byte string, and w is a member of the set {4, 16}, then
 * the function outputs an array of out_len integers between 0 and w - 1.
 *
 * Input parameters:
 *    X         byte string
 *    out_len   length of basew. It is REQUIRED to be less than or equal
 *                to 8 * len_X / lg(w)
 *    params    WOTS parameters (w, log2_w, n, len, len_1, hash_method)
 *
 * Output parameters:
 *    basew     resulted out_len-byte array
 */

/* clang-format off */
IPP_OWN_DEFN(void, cp_xmss_base_w, (const Ipp8u* X,
                                    Ipp32s out_len,
                                    Ipp8u* basew,
                                    cpWOTSParams* params))
/* clang-format on */
{
    Ipp32s in    = 0;
    Ipp32s out   = 0;
    Ipp32u total = 0;
    Ipp32s bits  = 0;
    for (Ipp32s consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = X[in];
            in++;
            bits += /*bit size of 1 byte*/ 8;
        }
        bits -= params->log2_w;
        basew[out] = (Ipp8u)((total >> bits) & (params->w - 1));
        out++;
    }
}

/*
 * Generates pseudorandom output of length n from an n-byte key and a 32-byte index
 * using hash functions as follows
 * Hash(toByte(padding_id, n) || key || msg)
 *
 * Returns:
 *    result of ippsHashMessage_rmf
 *
 * Input parameters:
 *    padding_id   32-byte value that is used as a padding value for a hash function
 *    key          n-byte key for the hash function
 *    msg          byte array
 *    msgLen       length of msg
 *    temp_buf     temporary memory (size is 2 * n + msgLen bytes at least)
 *    params       WOTS parameters (w, log2_w, n, len, len_1, hash_method)
 *
 * Output parameters:
 *    out          resulted n-byte array
 */

/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_do_xmss_hash, (Ipp32u padding_id,
                                          const Ipp8u* key,
                                          const Ipp8u* msg,
                                          Ipp32s msgLen,
                                          Ipp8u* out,
                                          Ipp8u* temp_buf,
                                          const cpWOTSParams* params))
/* clang-format on */
{

    cp_to_byte(temp_buf, params->n, padding_id);
    CopyBlock(key, temp_buf + params->n, params->n);
    CopyBlock(msg, temp_buf + 2 * params->n, msgLen);

    return ippsHashMessage_rmf(temp_buf, 2 * params->n + msgLen, out, params->hash_method);
}

/*
 * Generates pseudorandom output of length n from an n-byte key and a 32-byte index
 * using hash functions as follows
 * Hash(toByte(3, n) || key || msg)
 *
 * Input parameters:
 *    key          n-byte key for the hash function
 *    msg          32-byte array
 *    temp_buf     temporary memory (size is 2 * n + 32 bytes at least)
 *    params       WOTS parameters (w, log2_w, n, len, len_1, hash_method)
 *
 * Output parameters:
 *    out          resulted n-byte array
 */

/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_xmss_prf, (const Ipp8u* key,
                                      const Ipp8u* msg,
                                      Ipp8u* out,
                                      Ipp8u* temp_buf,
                                      const cpWOTSParams* params))
/* clang-format on */
{
    return cp_do_xmss_hash(/*prf function padding id*/ 3,
                           key,
                           msg,
                           /*byte size of index*/ ADRS_SIZE,
                           out,
                           temp_buf,
                           params);
}

/*
 * Generates pseudorandom output of length n from an n-byte key and a 32-byte index
 * using hash functions for key generation only as follows
 * Hash(toByte(4, n) || key || msg)
 *
 * Input parameters:
 *    key          n-byte key for the hash function
 *    msg          byte array
 *    msgLen       length of msg
 *    temp_buf     temporary memory (size is 2 * n + msgLen bytes at least)
 *    params       WOTS parameters (w, log2_w, n, len, len_1, hash_method)
 *
 * Output parameters:
 *    out          resulted n-byte array
 */

/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_xmss_prf_keygen, (const Ipp8u* key,
                                             const Ipp8u* msg,
                                             Ipp32s msgLen,
                                             Ipp8u* out,
                                             Ipp8u* temp_buf,
                                             const cpWOTSParams* params))
/* clang-format on */
{
    return cp_do_xmss_hash(/*prf_keygen function padding id*/ 4,
                           key,
                           msg,
                           msgLen,
                           out,
                           temp_buf,
                           params);
}

/*
 * Computes an iteration of F on an n-byte X using outputs of PRF. It takes an
 * OTS hash address (adrs) as input. This address will have the first six
 * 32-bit words set to encode the address of this chain. In each iteration, PRF
 * is used to generate a key for F and a bitmask that is XORed to the
 * intermediate result before it is processed by F. In the following, pSeed is an
 * n-byte string. To generate the keys and bitmasks, PRF is called with
 * pSeed as key and adrs as input. The chaining function also takes as input
 * a start index i, a number of steps s. The chaining function returns as output the array
 * obtained by iterating F for s times on input X, using the outputs of PRF.)
 *
 * temp_buf size is 4 * n bytes at least.
 */

/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_xmss_chain, (Ipp8u * X,
                                        Ipp8u i,
                                        Ipp8u s,
                                        Ipp8u* pSeed,
                                        Ipp8u* adrs,
                                        Ipp8u* out,
                                        Ipp8u* temp_buf,
                                        const cpWOTSParams* params))
/* clang-format on */
{
    IppStatus retCode = ippStsNoErr;
    Ipp8u* bm         = temp_buf;
    Ipp8u* key        = bm;
    CopyBlock(X, out, params->n);

    for (Ipp8u k = i; k < (i + s) && k < params->w; k++) {
        cp_xmss_set_hash_address(adrs, k);

        // BM = PRF(SEED, ADRS);
        cp_xmss_set_key_and_mask(adrs, /*bitmask for bm*/ 1);
        retCode = cp_xmss_prf(pSeed, adrs, bm, temp_buf + params->n, params);
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

        // out = out ^ BM;
        for (Ipp32s j = 0; j < params->n; ++j) {
            out[j] = out[j] ^ bm[j];
        }

        // KEY = PRF(SEED, ADRS);
        cp_xmss_set_key_and_mask(adrs, /*bitmask for key*/ 0);
        retCode = cp_xmss_prf(pSeed, adrs, key, temp_buf + params->n, params);
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

        // tmp = F(KEY, out);
        retCode = cp_do_xmss_hash(/*F function padding id*/ 0,
                                  key,
                                  out,
                                  params->n,
                                  out,
                                  temp_buf + params->n,
                                  params);
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
    }
    cp_xmss_set_hash_address(adrs, 0);
    return retCode;
}

/*
 * In order to verify a signature sig on a message M, the verifier
 * computes a WOTS+ public key value from the signature. This can be
 * done by "completing" the chain computations starting from the
 * signature values, using the base params->w values of the message hash and its
 * checksum. An OTS hash address adrs and a seed pSeed have to be provided by the calling
 * algorithm. This address will encode the address of the WOTS+ key
 * pair within a greater structure. Hence, a WOTS+ algorithm MUST NOT
 * manipulate any parts of adrs except for the last three 32-bit words.
 * Please note that the pSeed used here is public information also
 * available to a verifier.
 *
 * temp_buf size is (2 * params->len - params->len_1 + 4 * n) bytes at least.
 *
 * Output parameters:
 *    out   resulted len * n bytes array that contains WOTS+ public key
 *
 */

/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_xmss_WOTS_pkFromSig, (const Ipp8u* M,
                                                 Ipp8u* sig,
                                                 Ipp8u* pSeed,
                                                 Ipp8u* adrs,
                                                 Ipp8u* out,
                                                 Ipp8u* temp_buf,
                                                 cpWOTSParams* params))
/* clang-format on */
{
    IppStatus retCode = ippStsNoErr;
    // Convert message to base w
    Ipp32s len_2 = params->len - params->len_1;
    Ipp8u* msg   = temp_buf;
    cp_xmss_base_w(M, params->len_1, msg, params);

    // Compute checksum
    Ipp32u csum = 0;
    for (Ipp32s i = 0; i < params->len_1; i++) {
        csum = csum + params->w - 1 - msg[i];
    }

    // Convert csum to base w
    csum               = csum << (8 - ((len_2 * params->log2_w) & 7));
    Ipp32s len_2_bytes = cp_xmss_ceil((len_2 * params->log2_w) / 8.0);
    cp_to_byte(msg + params->len, len_2_bytes, csum);
    cp_xmss_base_w(msg + params->len, len_2, msg + params->len_1, params);

    for (Ipp32s i = 0; i < params->len; i++) {
        cp_xmss_set_chain_address(adrs, (Ipp8u)i);
        retCode = cp_xmss_chain(sig + i * params->n,
                                msg[i],
                                (Ipp8u)(params->w - 1 - msg[i]),
                                pSeed,
                                adrs,
                                out + (i * params->n),
                                temp_buf + (params->len + len_2),
                                params);
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
    }
    // null chain address for next call
    cp_xmss_set_chain_address(adrs, 0);
    return retCode;
}

/*
 * Generates byteSize random Ipp8u numbers using rndFunc and pRndParam parameters.
 * If rndFunc is NULL the function uses library-based solutions by default.
 *
 * Output parameters:
 *    out   resulted byteSize bytes array with random numbers
 */

/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_xmss_rand_num, (Ipp8u* out,
                                           Ipp32s byteSize,
                                           IppBitSupplier rndFunc,
                                           void* pRndParam))
/* clang-format on */
{

    int bitSize = byteSize * /*bit size of 1 byte*/ 8;
    if (rndFunc == NULL) {
        return ippsPRNGenRDRAND((Ipp32u*)out, bitSize, pRndParam);
    }
    return rndFunc((Ipp32u*)out, bitSize, pRndParam);
}

/*
 * Generates the WOTS+ secret key.
 *
 * temp_buf size is (n + 32 + 2 * n + n + 32 = 4 * n + 64) bytes at least.
 *
 * Output parameters:
 *    out   resulted n bytes array that contains WOTS+ secret key
 *
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_xmss_WOTS_genSK, (Ipp8u* pSecretSeed,
                                             Ipp8u* pPublicSeed,
                                             Ipp8u* adrs,
                                             Ipp8u* out,
                                             Ipp8u* temp_buf,
                                             const cpWOTSParams* params))
/* clang-format on */
{
    Ipp32s n            = params->n;
    Ipp8u* temp_for_prf = temp_buf + (n + ADRS_SIZE);
    // sk[i] = PRFkeygen(S_XMSS, SEED || ADRS);
    CopyBlock(pPublicSeed, temp_buf, n);
    CopyBlock(adrs, temp_buf + n, ADRS_SIZE);
    return cp_xmss_prf_keygen(pSecretSeed, temp_buf, n + ADRS_SIZE, out, temp_for_prf, params);
}

/*
 * Generates the WOTS+ public key.
 *
 * temp_buf size is (7 * n + 32) bytes at least.
 *
 * Output parameters:
 *    pPublicKey   resulted len * n bytes array that contains WOTS+ public key
 *
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_xmss_WOTS_genPK, (Ipp8u* pSecretSeed,
                                             Ipp8u* pPublicKey,
                                             Ipp8u* pPublicSeed,
                                             Ipp8u* adrs,
                                             Ipp8u* temp_buf,
                                             const cpWOTSParams* params))
/* clang-format on */
{
    IppStatus retCode = ippStsNoErr;
    Ipp32s n          = params->n;
    Ipp32s len        = params->len;
    Ipp8u* sk         = temp_buf;
    for (Ipp32s i = 0; i < len; i++) {
        // generate secret key from secret seed
        cp_xmss_set_chain_address(adrs, (Ipp8u)i);
        retCode = cp_xmss_WOTS_genSK(pSecretSeed,
                                     pPublicSeed,
                                     adrs,
                                     sk,
                                     temp_buf + n,
                                     params); // 4 * n + 64
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

        // chaining
        retCode = cp_xmss_chain(sk,
                                (Ipp8u)0,
                                (Ipp8u)(params->w - 1),
                                pPublicSeed,
                                adrs,
                                pPublicKey + (i * n),
                                temp_buf + n,
                                params);
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
    }
    // null chain address for next call
    cp_xmss_set_chain_address(adrs, 0);
    return retCode;
}

/*
 * Generates the WOTS+ signature for the message M using pSecretSeed.
 *
 * temp_buf size is (7 * n + len) bytes at least.
 *
 * Output parameters:
 *    pSignature   resulted len * n bytes array that contains WOTS+ public key
 *
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_xmss_WOTS_sign, (const Ipp8u* M,
                                            Ipp8u* pSecretSeed,
                                            Ipp8u* pSignature,
                                            Ipp8u* pPublicSeed,
                                            Ipp8u* adrs,
                                            Ipp8u* temp_buf,
                                            cpWOTSParams* params))
/* clang-format on */
{
    IppStatus retCode = ippStsNoErr;
    // Convert message to base w
    Ipp32s len   = params->len;
    Ipp32s len_1 = params->len_1;
    Ipp32s len_2 = len - len_1;
    Ipp32s n     = params->n;
    Ipp8u* msg   = temp_buf;
    cp_xmss_base_w(M, params->len_1, msg, params);

    // Compute checksum
    Ipp32u csum = 0;
    for (Ipp32s i = 0; i < params->len_1; i++) {
        csum = csum + params->w - 1 - msg[i];
    }

    // Convert csum to base w
    csum               = csum << (8 - ((len_2 * params->log2_w) & 7));
    Ipp32s len_2_bytes = cp_xmss_ceil((len_2 * params->log2_w) / 8.0);
    cp_to_byte(msg + len, len_2_bytes, csum);
    cp_xmss_base_w(msg + len, len_2, msg + len_1, params);

    Ipp8u* sk = temp_buf + len;
    for (Ipp32s i = 0; i < len; i++) {
        // generate secret key from secret seed
        // sk[j] = PRFkeygen(S_XMSS, SEED || ADRS);
        cp_xmss_set_chain_address(adrs, (Ipp8u)i);
        retCode =
            cp_xmss_WOTS_genSK(pSecretSeed, pPublicSeed, adrs, sk, sk + n, params); // 4 * n + 64
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)

        // chaining
        retCode = cp_xmss_chain(sk,
                                (Ipp8u)0,
                                msg[i],
                                pPublicSeed,
                                adrs,
                                pSignature + (i * n),
                                sk + n,
                                params);
        IPP_BADARG_RET((ippStsNoErr != retCode), retCode)
    }
    // null chain address for next call
    cp_xmss_set_chain_address(adrs, 0);
    return retCode;
}
