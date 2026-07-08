/*************************************************************************
* Copyright (C) 2026 Intel Corporation
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
#include "pcpbn.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"
#include "drbg/pcphashdrbg.h"
#include "pcptool.h"

/* Returns a mask of BNU_CHUNK_T type based on the condition (nsA < nsB):
 * - 0xFFFFFFFF, if the condition is true,
 * - 0x00000000 otherwise.
 * The masks are used to avoid branches when one operand is shorter than the other. */
IPPCP_INLINE BNU_CHUNK_T maskFromCond(cpSize nsA, cpSize nsB)
{
    return (BNU_CHUNK_T)(-(BNS_CHUNK_T)(nsA < nsB));
}

/* to not lose carry use this function if nsA >= nsB (nsB >= 1) */
IPPCP_INLINE void cpAddWithCarry_BNU(BNU_CHUNK_T* pR,
                                     const BNU_CHUNK_T* pA,
                                     cpSize nsA,
                                     const BNU_CHUNK_T* pB,
                                     cpSize nsB)
{
    BNU_CHUNK_T carry = 0;

    for (int i = 0; i < nsA; i++) {
        /* m is all-ones while i < nsB, else 0 */
        BNU_CHUNK_T m = maskFromCond(i, nsB);
        /* clamp the pB index to 0 once i >= nsB so the load stays in bounds;
           the value is masked to 0 anyway, so the result is unchanged */
        cpSize idxB   = i & (cpSize)m;
        BNU_CHUNK_T b = pB[idxB] & m;

        ADD_ABC(carry, pR[i], pA[i], b, carry);
    }
}

static void cpEndiannessReverseInplace(Ipp8u* arr, const int len)
{
#define SWAPXOR(x, y) \
    (x) ^= (y);       \
    (y) ^= (x);       \
    (x) ^= (y);

    for (int i = 0; i < len / 2; ++i) {
        SWAPXOR(arr[i], arr[len - 1 - i])
    }
    return;
#undef SWAPXOR
}

/*
 * The Hashgen Process as listed in SP800-90Ar1 10.1.1.4.
 * Generates pseudorandom numbers and put them into resulted array
 *
 * Input parameters:
 *  outputLen32         the number of 32-bit dwords to be returned
 *  pDrbg               pointer to the DRBG state
 *
 * Output parameters:
 *  output              generated 32-bit numbers to be returned to the cpHashDRBG_Gen function
 *
 * NIST.SP.800-90Ar1. Section 10.1.1.4 Generating Pseudorandom Bits Using Hash_DRBG
 *
 * Hashgen Process:
 *      data = V
 *      w = NULL
 *      for (i = 1 to m) {
 *          W = W || Hash(data)
 *          data = (data + 1) mod (2^seedlen)
 *      }
 *      out = leftmost(W, requested_no_of_bits)
 *      Return (returned_bits)
*/

static IppStatus cpHashGen(Ipp32u* output, int outputLen32, IppsHashDRBGState* pDrbg)
{
    IppStatus sts = ippStsNoErr;

    int seedBytesExtLen = BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN_EXT(pDrbg));

    Ipp32u* pW            = output;
    Ipp8u* pTempBuf       = pDrbg->tempBuf;
    BNU_CHUNK_T* pBN_data = (BNU_CHUNK_T*)pDrbg->tempBuf;

    COPY_BNU(pDrbg->tempBuf, pDrbg->V, seedBytesExtLen);

    int outputHash_wLen = pDrbg->pHashMethod->hashLen / 4; // WORD8 -> WORD32

    int residual = outputLen32;
    while (residual > 0) {
        /* w = Hash (data) */
        sts = ippsHashInit_rmf(pDrbg->hashState, pDrbg->pHashMethod);
        sts |= ippsHashUpdate_rmf(1 + pTempBuf,
                                  BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN(pDrbg)),
                                  pDrbg->hashState);
        sts |= ippsHashFinal_rmf(pDrbg->hashOutputBuf, pDrbg->hashState);
        if (sts != ippStsNoErr) {
            /* zeroize tempBuf */
            PurgeBlock((void*)pDrbg->tempBuf, seedBytesExtLen);
            return ippStsHashOperationErr;
        }

        /* W = W || w */
        COPY_BNU(pW, (Ipp32u*)pDrbg->hashOutputBuf, IPP_MIN(residual, outputHash_wLen));

        pW += outputHash_wLen;
        residual -= outputHash_wLen;

        if (residual > 0) {
            /* data = (data + 1) mod 2^seedlen */
            /* Little Endian to Big Endian */
            cpEndiannessReverseInplace(pTempBuf, seedBytesExtLen);
            cpInc_BNU(pBN_data, pBN_data, BITS_BNU_CHUNK(HASH_DRBG_SEEDBITS_LEN(pDrbg)), 1);
            /* Big Endian to Little Endian */
            cpEndiannessReverseInplace(pTempBuf, seedBytesExtLen);
            /* applying (data mod 2^seed_bits_len) == pBN_data[seed_bytes_len-1] &= 0xffff */
            // zero out the zeroth element if single bites are added there due to overflow
            pTempBuf[0] = 0;
        }
    }

    /* zeroize tempBuf since it's no longer needed */
    PurgeBlock((void*)pDrbg->tempBuf, seedBytesExtLen);

    return sts;
}

/*
 * The Hash_DRBG_Generate Process as listed in SP800-90Ar1 10.1.1.4.
 * Hashes input data, updates V and returns the requested number of bytes
 *
 * Input parameters:
 *  randLen32         the number of 32-bit dwords to be returned
 *  addlInput         pointer to the array containing additional input (optional)
 *  addlInputBitsLen  length of the addlInput in bits (may be zero)
 *  pDrbg             pointer to the DRBG state
 *
 * Output parameters:
 *  pRand              resulted array for 32-bit pseudorandom numbers
 *
 * NIST.SP.800-90Ar1. Section 10.1.1.4 Generating Pseudorandom Bits Using Hash_DRBG
 *
 * Hash_DRBG_Generate Process:
 *      if (reseed_counter > reseed_interval)
 *          return 1; // reseed required
 *      if (additional_input != NULL) {
 *          w = Hash (0x02 || V || additional_input)
 *          V = (V + w) mod 2^seedlen
 *      }
 *      (returned_bits) = Hashgen (requested_number_of_bits, V)
 *      H = Hash (0x03 || V)
 *      V = (V + H + C + reseed_counter) mod 2^seedlen
 *      reseed_counter = reseed_counter + 1
 *      Return (SUCCESS, returned_bits, V, C, reseed_counter)
*/

IPP_OWN_DEFN(IppStatus,
             cpHashDRBG_Gen,
             (Ipp32u * pRand,
              cpSize randLen32,
              const int predictionResistanceRequest,
              const Ipp8u* addlInput,
              const int addlInputBitsLen,
              IppsHashDRBG_EntropyInputCtx* pEntrInputCtx,
              IppsHashDRBGState* pDrbg))
{
    IppStatus sts = ippStsNoErr;

    int addlInputBitsLenTmp = addlInputBitsLen;

    /* A reseed is required if
       1) reseed_counter > MAX_RESEED_INTERVAL
          (NIST.SP.800-90Ar1 Section 9.3.2 "Reseeding at the End of the Seedlife");
       2) prediction resistance is requested. */
    if ((HASH_DRBG_RESEED_COUNTER(pDrbg) > MAX_RESEED_INTERVAL) || predictionResistanceRequest) {
        sts = ippsHashDRBG_Reseed(predictionResistanceRequest,
                                  addlInput,
                                  addlInputBitsLenTmp,
                                  pEntrInputCtx,
                                  pDrbg);
        if (ippStsNoErr != sts) {
            return sts;
        }
        addlInput           = NULL;
        addlInputBitsLenTmp = 0;
    }

    int seedBytesLen    = BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN(pDrbg));
    int seedBytesExtLen = BITS2WORD8_SIZE(HASH_DRBG_SEEDBITS_LEN_EXT(pDrbg));

    Ipp8u* pV = pDrbg->V;

    __ALIGN64 Ipp8u reseedCnt[8];

    /* present unsigned long long in big-endian format */
    reseedCnt[0] = (Ipp8u)((HASH_DRBG_RESEED_COUNTER(pDrbg) >> 56) & 0xFF);
    reseedCnt[1] = (Ipp8u)((HASH_DRBG_RESEED_COUNTER(pDrbg) >> 48) & 0xFF);
    reseedCnt[2] = (Ipp8u)((HASH_DRBG_RESEED_COUNTER(pDrbg) >> 40) & 0xFF);
    reseedCnt[3] = (Ipp8u)((HASH_DRBG_RESEED_COUNTER(pDrbg) >> 32) & 0xFF);
    reseedCnt[4] = (Ipp8u)((HASH_DRBG_RESEED_COUNTER(pDrbg) >> 24) & 0xFF);
    reseedCnt[5] = (Ipp8u)((HASH_DRBG_RESEED_COUNTER(pDrbg) >> 16) & 0xFF);
    reseedCnt[6] = (Ipp8u)((HASH_DRBG_RESEED_COUNTER(pDrbg) >> 8) & 0xFF);
    reseedCnt[7] = (Ipp8u)(HASH_DRBG_RESEED_COUNTER(pDrbg) & 0xFF);

    int outputHashBufLen = pDrbg->pHashMethod->hashLen;

    Ipp8u prefix;

    if (addlInputBitsLenTmp) {
        /*
            w = Hash (0x02 || V || addlInput)
            V = (V + w) mod 2^seedlen
        */
        prefix = 2;
        sts    = ippsHashInit_rmf(pDrbg->hashState, pDrbg->pHashMethod);
        sts |= ippsHashUpdate_rmf(&prefix, sizeof(prefix), pDrbg->hashState);
        sts |= ippsHashUpdate_rmf(pV + 1, seedBytesLen, pDrbg->hashState);
        sts |=
            ippsHashUpdate_rmf(addlInput, BITS2WORD8_SIZE(addlInputBitsLenTmp), pDrbg->hashState);
        sts |= ippsHashFinal_rmf(pDrbg->hashOutputBuf, pDrbg->hashState) != ippStsNoErr;
        if (sts != ippStsNoErr) {
            return ippStsHashOperationErr;
        }

        BNU_CHUNK_T* pBN_V = (BNU_CHUNK_T*)pDrbg->V;

        /* V = V + w */
        /* Little Endian to Big Endian */
        cpEndiannessReverseInplace(pV, seedBytesExtLen);
        /* Little Endian to Big Endian */
        cpEndiannessReverseInplace(pDrbg->hashOutputBuf, outputHashBufLen);
        cpAddWithCarry_BNU(pBN_V,
                           pBN_V,
                           BITS_BNU_CHUNK(HASH_DRBG_SEEDBITS_LEN(pDrbg)),
                           (BNU_CHUNK_T*)pDrbg->hashOutputBuf,
                           BITS_BNU_CHUNK(pDrbg->pHashMethod->hashLen * BYTESIZE));
        /* Big Endian to Little Endian */
        cpEndiannessReverseInplace(pV, seedBytesExtLen);

        /* V mod 2^seedlen */
        pV[0] = 0;
    }
    /* Hashgen (requested_number_of_bits, V) */
    sts = cpHashGen(pRand, randLen32, pDrbg);
    if (ippStsNoErr != sts) {
        return sts;
    }

    /* H = Hash (0x03 || V) */
    prefix = 3;

    sts = ippsHashInit_rmf(pDrbg->hashState, pDrbg->pHashMethod);
    sts |= ippsHashUpdate_rmf(&prefix, sizeof(prefix), pDrbg->hashState);
    sts |= ippsHashUpdate_rmf(pV + 1, seedBytesLen, pDrbg->hashState);
    sts |= ippsHashFinal_rmf(pDrbg->hashOutputBuf, pDrbg->hashState);
    if (sts != ippStsNoErr) {
        return ippStsHashOperationErr;
    }

    /* V = (V + H + C + reseedCounter) mod 2^seedlen */
    BNU_CHUNK_T* pBN_V = (BNU_CHUNK_T*)pDrbg->V;

    /* Little Endian to Big Endian */
    cpEndiannessReverseInplace(pV, seedBytesExtLen);
    /* Little Endian to Big Endian */
    cpEndiannessReverseInplace(pDrbg->hashOutputBuf, outputHashBufLen);
    /* V + H */
    cpAddWithCarry_BNU(pBN_V,
                       pBN_V,
                       BITS_BNU_CHUNK(HASH_DRBG_SEEDBITS_LEN(pDrbg)),
                       (BNU_CHUNK_T*)pDrbg->hashOutputBuf,
                       BITS_BNU_CHUNK(pDrbg->pHashMethod->hashLen * BYTESIZE));

    /* Little Endian to Big Endian */
    cpEndiannessReverseInplace(pDrbg->C, seedBytesLen);
    /* V + C */
    cpAdd_BNU(pBN_V, pBN_V, (BNU_CHUNK_T*)pDrbg->C, BITS_BNU_CHUNK(HASH_DRBG_SEEDBITS_LEN(pDrbg)));
    /* Big Endian to Little Endian */
    cpEndiannessReverseInplace(pDrbg->C, seedBytesLen);

    /* Little Endian to Big Endian */
    cpEndiannessReverseInplace(reseedCnt, sizeof(reseedCnt));
    /* V + reseedCnt */
    cpAddWithCarry_BNU(pBN_V,
                       pBN_V,
                       BITS_BNU_CHUNK(HASH_DRBG_SEEDBITS_LEN(pDrbg)),
                       (BNU_CHUNK_T*)reseedCnt,
                       BITS_BNU_CHUNK(BITSIZE(reseedCnt)));

    /* Big Endian to Little Endian */
    cpEndiannessReverseInplace(pV, seedBytesExtLen);

    /* V mod 2^seedlen */
    pV[0] = 0;

    /* reseed_counter = reseed_counter + 1 */
    HASH_DRBG_RESEED_COUNTER(pDrbg)++;

    return sts;
}
