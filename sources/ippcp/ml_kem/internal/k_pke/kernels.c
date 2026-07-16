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

/*
 * Stuff functions definition
 */

#include "owncp.h"
#include "owndefs.h"
#include "ippcpdefs.h"
#include "stateless_pqc/ml_kem_internal/ml_kem.h"

#define CP_D_MAX (12)
#define CP_D_MIN (1)

//-------------------------------//
//      Internal functions
//-------------------------------//

/*
 * Algorithm 3: Converts a bit array (of a length that is a multiple of eight) into an array of bytes.
 *
 * Input: bit array {0, 1}^{8*l}
 * Output: byte array B^l
 *
 * Note: works inplace (pInp == pOut), buffer's length has to be numElmBitArr bytes
 */
IPPCP_INLINE void cp_bitsToBytes(const Ipp8u* pInp, Ipp8u* pOut, const Ipp32u numElmBitArr)
{
    IPPCP_GCC_IGNORE_PUSH("-Wmaybe-uninitialized")
    Ipp32u numElmByteArr = BITS2WORD8_SIZE(numElmBitArr);
    for (Ipp32u i = 0; i < numElmByteArr; i++) {
        Ipp8u B = 0;
        for (Ipp32u j = 0; j < 8; j++) {
            B = B + (Ipp8u)(pInp[8 * i + j] << j);
        }
        pOut[i] = B;
    }
    IPPCP_GCC_IGNORE_POP
}

/*
 * Algorithm 4: Performs the inverse of cp_bitsToBytes, converting a byte array into a bit array.
 *
 * Input: byte array B^l
 * Output: bit array {0, 1}^{8*l}
 *
 * Note: doesn't work inplace (pInp == pOut).
 */
/* clang-format on */
IPPCP_INLINE IppStatus cp_bytesToBits(const Ipp8u* pInp,
                                      Ipp8u* pOut,
                                      const Ipp32u numElmByteArr,
                                      const Ipp32u outByteSize)
/* clang-format on */
{
    /* Check that the output buffer has enough space for write */
    IPP_BADARG_RET((8 * numElmByteArr > outByteSize), ippStsMemAllocErr);

    IPPCP_GCC_IGNORE_PUSH("-Wstringop-overflow")
    for (Ipp32u i = 0; i < numElmByteArr; i++) {
        Ipp8u C = pInp[i];
        for (Ipp32u j = 0; j < 8; j++) {
            pOut[8 * i + j] = (C >> j) & 1;
        }
    }
    IPPCP_GCC_IGNORE_POP

    return ippStsNoErr;
}

/*
 * Formula 4.7: Compressing primitive
 *
 * Input:  in  - number in Z_{q}, q = 3329
 *         d   - decompression base {1, 2, ..., 11}
 * Output: out - number in Z_{2^{d}}
 *
 * Z_{q} -> Z_{2^{d}}: x -> RoundToNearestInt((2^{d} / q) * x) mod 2^{d}
*/
IPP_OWN_DEFN(IppStatus, cp_Compress, (Ipp16u * out, const Ipp16s in, const Ipp16u d))
{
    IPP_BADARG_RET(((d < CP_D_MIN) || (d >= CP_D_MAX)), ippStsOutOfRangeErr);

    /* transform numbers from the Barrett reduced form to positive representation */
    Ipp16s u = in;
    u += (u >> 15) & CP_ML_KEM_Q;

    /* Constant-time compression: round(u * 2^d / 3329) mod 2^d
     * To avoid variable-time integer division, the operation is computed as
     * floor((u * 2^d + offset) * M / 2^S). The constants (offset, M, S) are
     * derived for each 'd' to ensure the approximation error over u \in [0, 3328]
     * is strictly bounded, guaranteeing exact equivalence to FIPS 203.
     */
    Ipp64u d0 = (Ipp64u)u << d;
    switch (d) {
    case 1:
    case 4:
        d0 += 1665;
        d0 *= 80635;
        d0 >>= 28;
        break;
    case 5:
        d0 += 1664;
        d0 *= 40318;
        d0 >>= 27;
        break;
    case 10:
        d0 += 1665;
        d0 *= 1290167;
        d0 >>= 32;
        break;
    case 11:
        d0 += 1664;
        d0 *= 645084;
        d0 >>= 31;
        break;
    default:
        /* Fallback for non-standard d */
        d0 = (d0 + 1664) / CP_ML_KEM_Q;
        break;
    }

    *out = (Ipp16u)(d0 & ((1U << d) - 1));

    return ippStsNoErr;
}

/*
 * Formula 4.8: Decompressing primitive
 *
 * Input:  in  - number in Z_{2^{d}}
 *         d   - decompression base {1, 2, ..., 11}
 * Output: out - number in Z_{q}, q = 3329
 *
 * Z_{2^{d}} -> Z_{q}: y -> RoundToNearestInt((q / 2^{d}) * y)
*/

IPP_OWN_DEFN(IppStatus, cp_Decompress, (Ipp16u * out, const Ipp16s in, const Ipp16u d))
{
    IPP_BADARG_RET(((d < CP_D_MIN) || (d >= CP_D_MAX)), ippStsOutOfRangeErr);

    /* transform numbers from the Barrett reduced form to positive representation */
    Ipp16s u = in;
    u += (u >> 15) & CP_ML_KEM_Q;

    /* Constant-time decompression: round(u * 3329 / 2^d) 
     * Since 2^d is a power of 2, division is an exact right-shift.
     * Max value of u * 3329 is 2047 * 3329 = ~6.8M, which safely fits in Ipp32u.
     */
    Ipp32u t = (Ipp32u)u * CP_ML_KEM_Q;
    t += (1U << (d - 1));
    t >>= d;
    *out = (Ipp16u)t;

    return ippStsNoErr;
}

/*
 * Algorithm 5: Encodes an array of d-bit integers into a byte array for 1 <= d <= 12.
 *
 * Input:  pPolyF - integer array F in Z_{m}^{256}, where each m = 2^d if d < 12, otherwise m = q.
 *         d      - parameter specifying the number of bits.
 * Output: B      - byte array B^{32*d}.
 *
 * Note: To reduce memory usage, the result is processed by chunk of size lcm(d, 8)
         which is suitable for any d(maximum chunk of size 88 is required for d = 11)
 */

// Allow bigger buffer allocation for the latest platforms to speed up processing
#if CP_ML_KEM_MEMORY_OPTIMIZED
#define CP_B_BUFFERSIZE_MAX (88)
#else
#define CP_B_BUFFERSIZE_MAX (32 * 8 * CP_D_MAX)
#endif /* #if CP_ML_KEM_MEMORY_OPTIMIZED */

IPP_OWN_DEFN(IppStatus, cp_byteEncode, (Ipp8u * B, const Ipp16u d, const Ipp16sPoly* pPolyF))
{
    IPP_BADARG_RET(((d < CP_D_MIN) || (d > CP_D_MAX)), ippStsOutOfRangeErr);

    Ipp32u bits_accumulated = 0;
    Ipp8u b[CP_B_BUFFERSIZE_MAX];

    /* Encode polynomial to byte array */
    for (Ipp32u i = 0; i < 256; i++) {
        Ipp16u a = (Ipp16u)pPolyF->values[i];

        for (Ipp32u j = 0; j < d; j++, bits_accumulated++) {
            /* Similar to the spec's logic:
             *      b[bits_accumulated] = (a & 1);
             *      a                   = (a - b[bits_accumulated]) >> 1;
             * The original write-modify pattern was replaced with a direct bit extraction.
             */
            b[bits_accumulated] = (Ipp8u)((a >> j) & 1);
        }

// Process the buffer b to reuse the memory reduced for old platforms
#if CP_ML_KEM_MEMORY_OPTIMIZED
        /* Check if we filled the current chunk for cp_bitsToBytes processing */
        if ((bits_accumulated & 7) == 0) {
            cp_bitsToBytes(b, B, bits_accumulated);
            B += BITS2WORD8_SIZE(bits_accumulated);
            bits_accumulated = 0;
        }
#endif
    }


    /* Process the last chunk which may be 0 or not full(less than lcm(d, 8)) */
    cp_bitsToBytes(b, B, bits_accumulated);

    return ippStsNoErr;
}

/*
 * Algorithm 6: Decodes a byte array into an array of d-bit integers for 1 <= d <= 12.
 *
 * Input:  d         - parameter specifying the number of bits.
 *         B         - byte array B^{32*d}.
 *         bByteSize - the size of the input byte array B in bytes.
 * Output: pPolyF    - integer array F in Z_{m}^{256}, where each m = 2^d if d < 12, otherwise m = q.
 *
 * Note: To reduce memory usage, the input byte array is processed by chunk of size d*8.
 */
#if CP_ML_KEM_MEMORY_OPTIMIZED
#define BITS_BUFFER_BYTESIZE (8 * CP_D_MAX)
#else
#define BITS_BUFFER_BYTESIZE (32 * 8 * CP_D_MAX)
#endif
IPP_OWN_DEFN(IppStatus,
             cp_byteDecode,
             (Ipp16sPoly * pPolyF, const Ipp16u d, const Ipp8u* B, const int bByteSize))
{
    IPP_BADARG_RET(((d < CP_D_MIN) || (d > CP_D_MAX)), ippStsOutOfRangeErr);
    IPP_BADARG_RET((bByteSize < 32 * d), ippStsOutOfRangeErr);

    IppStatus sts = ippStsNoErr;
    Ipp8u bitsArr[BITS_BUFFER_BYTESIZE];

/* Batched processing of all bytes from B to bitsArr -
   read all 32*d bytes from B and put 8*32*d elements in bitsArr */
#if !CP_ML_KEM_MEMORY_OPTIMIZED
    sts = cp_bytesToBits(B, bitsArr, 32 * d, BITS_BUFFER_BYTESIZE);
    if (sts != ippStsNoErr) {
        return sts;
    }
#endif

    /* Decode byte array to polynomial */
    for (Ipp32u i = 0; i < 256; i++) {
        Ipp32u bitsArrIdx = i;

#if CP_ML_KEM_MEMORY_OPTIMIZED
        if ((i & 7) == 0) {
            // Read the next d bytes from B and put 8*d elements in bitsArr
            sts |= cp_bytesToBits(B, bitsArr, d, BITS_BUFFER_BYTESIZE);
            B += d;
        }
        bitsArrIdx = (i & 7);
#endif

        pPolyF->values[i] = 0;
        for (Ipp32u j = 0; j < d; j++) {
            pPolyF->values[i] += bitsArr[bitsArrIdx * d + j] << j;
        }
    }

    return sts;
}

/*
 * Algorithm 8: Takes a seed as input and outputs a pseudorandom sample from the distribution D_{eta}(R_{q}).
 *
 * Input:  pSeed  - byte array B^{64*eta}
 *         eta    - the value of eta, can be 1, 2 or 3
 * Output: pPoly  - array Z_{q}^{256} with values sampled from the distribution D_{eta}(R_{q}).
 *
 */
#if CP_ML_KEM_MEMORY_OPTIMIZED
#define SEED_BITS_BUFFER_BYTESIZE (4 * 8 * CP_ML_KEM_ETA_MAX)
#else
#define SEED_BITS_BUFFER_BYTESIZE (64 * 8 * CP_ML_KEM_ETA_MAX)
#endif
IPP_OWN_DEFN(IppStatus, cp_samplePolyCBD, (Ipp16sPoly * pPoly, const Ipp8u* pSeed, const Ipp8u eta))
{
    IppStatus sts = ippStsNoErr;
    /* Byte array (the size is different for the different platform) */
    Ipp8u seedBits[SEED_BITS_BUFFER_BYTESIZE];

/* Batched processing of all bytes from pSeed to seedBits -
   read all 64*eta bytes from pSeed and put 8*64*eta elements in seedBits */
#if !CP_ML_KEM_MEMORY_OPTIMIZED
    sts = cp_bytesToBits(pSeed, seedBits, 64 * eta, SEED_BITS_BUFFER_BYTESIZE);
    if (sts != ippStsNoErr) {
        return sts;
    }
#endif

    for (Ipp16u i = 0; i < 256; i++) {
        Ipp32u seedBitsIdx = i;

/* Convert part of bytes to bits for the memory optimization -
   read 2*eta bytes from pSeed and put 8*2*eta elements in seedBits */
#if CP_ML_KEM_MEMORY_OPTIMIZED
        if ((i & 7) == 0) {
            sts |= cp_bytesToBits(pSeed, seedBits, 2 * eta, SEED_BITS_BUFFER_BYTESIZE);
            pSeed += 2 * eta;
        }
        seedBitsIdx = (i & 7);
#endif

        Ipp16s x = 0;
        Ipp16s y = 0;
        for (Ipp8u j = 0; j < eta; j++) {
            x += seedBits[2 * seedBitsIdx * eta + j];
            y += seedBits[2 * seedBitsIdx * eta + eta + j];
        }

        // The result will be mapped to the canonical positive representation in the reduction step
        Ipp16s result    = x - y;
        pPoly->values[i] = cp_mlkemBarrettReduce((Ipp32s)result);
    }

    return sts;
}
