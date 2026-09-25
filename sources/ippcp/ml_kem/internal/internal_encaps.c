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

//-------------------------------//
//      Level 1 functions
//-------------------------------//

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"
#include "stateless_pqc/ml_kem_internal/ml_kem.h"

/*
 * Checks that all encoded polynomial coefficients in the encapsulation key are less than q.
 *
 *      inpEncKey - input pointer to the encapsulation key (public key) of size 384*k + 32 bytes
 *      mlkemCtx  - input pointer to ML KEM context
 */
IPP_OWN_DEFN(IppStatus, cp_MLKEMEncapsKeyCheck, (const Ipp8u* inpEncKey, IppsMLKEMState* mlkemCtx))
{
    const Ipp8u k = mlkemCtx->params.k;

    /* Section 7.2, encapsulation key check, step 2 (modulus check) */
    /*
     * The FIPS 203 ByteDecode12/ByteEncode12 round trip preserves the
     * encoding exactly when every decoded 12-bit coefficient is less than q.
     * Process two coefficients from each three-byte group.
     */
    const Ipp32u coefficientMask = 0x0FFFu;
    const Ipp32u invalidBit      = 1u << 15;
    const Ipp32u validityBias    = invalidBit - CP_ML_KEM_Q;
    const Ipp32u pairedBias      = validityBias | (validityBias << 16);
    const Ipp32u invalidBits     = invalidBit | (invalidBit << 16);
    Ipp32u invalid               = 0;

    for (int i = 0; i < 384 * k; i += 3) {
        /*
         * Arrange the coefficients in independent 16-bit lanes:
         * [ unused (4 bits) | c1 (12 bits) | unused (4 bits) | c0 (12 bits) ]
         */
        const Ipp32u packed =
            inpEncKey[i] | ((Ipp32u)inpEncKey[i + 1] << 8) | ((Ipp32u)inpEncKey[i + 2] << 16);
        const Ipp32u coefficients =
            (packed & coefficientMask) | ((packed << 4) & (coefficientMask << 16));

        /*
         * Adding 2^15-q sets the top bit of a lane exactly when c >= q.
         * The maximum lane result is 4095 + (2^15-q) = 0x82FE, so the low
         * lane cannot carry into the high lane.
         */
        invalid |= coefficients + pairedBias;
    }

    return (0 != (invalid & invalidBits)) ? ippStsBadArgErr : ippStsNoErr;
}

/*
 * Uses the encapsulation key and randomness to generate a key and an associated ciphertext.
 *
 *      K          - output pointer to the generated shared secret key K of size 32 bytes
 *      ciphertext - output pointer to the ciphertext of size 32*(d_{u}*k + d_{v})) bytes
 *      inpEncKey  - input pointer to the encapsulation key (public key) of size 384*k + 32 bytes
 *      m          - input parameter with generated randomness m of size 32 bytes
 *      mlkemCtx   - input pointer to ML KEM context
 */
/* clang-format off */
IPP_OWN_DEFN(IppStatus, cp_MLKEMencaps_internal, (Ipp8u K[CP_SHARED_SECRET_BYTES],
                                                  Ipp8u* ciphertext,
                                                  const Ipp8u* inpEncKey,
                                                  const Ipp8u m[CP_RAND_DATA_BYTES],
                                                  IppsMLKEMState* mlkemCtx))
/* clang-format on */
{
    IppStatus sts = ippStsNoErr;
    const Ipp8u k = mlkemCtx->params.k;

    /* (K,𝑟) <- G(m||H(ek)) */
    Ipp8u r_N[33];
    Ipp8u concatData[64];

    const Ipp32s ekByteSize     = 384 * k + 32;
    const Ipp32s ek_pkeByteSize = ekByteSize;

    /* H(ek) */
    sts = ippsHashMessage_rmf(inpEncKey, ek_pkeByteSize, r_N, ippsHashMethod_SHA3_256());
    if (sts != ippStsNoErr)
        goto exit;
    /* m||H(ek) */
    CopyBlock(m, concatData, CP_RAND_DATA_BYTES);
    CopyBlock(r_N, concatData + 32, 32);
    /* G(m||H(ek)) */
    sts = ippsHashMessage_rmf(concatData, 64, concatData, ippsHashMethod_SHA3_512());
    if (sts != ippStsNoErr)
        goto exit;

    CopyBlock(concatData, K, CP_SHARED_SECRET_BYTES);
    CopyBlock(concatData + CP_SHARED_SECRET_BYTES, r_N, 32);

    /* c <- K-PKE.Encrypt(ek, m, r) */
    sts = cp_KPKE_Encrypt(ciphertext, inpEncKey, m, r_N, mlkemCtx);

exit:
    /* Clear the copy of the secret */
    PurgeBlock(concatData, sizeof(concatData));
    PurgeBlock(r_N, sizeof(r_N));

    return sts;
}
