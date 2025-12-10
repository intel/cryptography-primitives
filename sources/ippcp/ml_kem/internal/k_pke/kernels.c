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
#include "ml_kem_internal/ml_kem.h"

#define CP_D_MAX (12)
#define CP_D_MIN (1)

/*
 * Perform division of x by divisor with the rounding of x to the nearest integer
 */
IPPCP_INLINE Ipp16s cp_divAndRoundToNearestInt(Ipp32s x, Ipp32s divisor)
{
    return (Ipp16s)((x + (divisor >> 1)) / divisor);
}

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
    Ipp32u numElmByteArr = BITS2WORD8_SIZE(numElmBitArr);
    for (Ipp32u i = 0; i < numElmByteArr; i++) {
        Ipp8u B = 0;
        for (Ipp32u j = 0; j < 8; j++) {
            B = B + (Ipp8u)(pInp[8 * i + j] << j);
        }
        pOut[i] = B;
    }
}

/*
 * Algorithm 4: Performs the inverse of cp_bitsToBytes, converting a byte array into a bit array.
 *
 * Input: byte array B^l
 * Output: bit array {0, 1}^{8*l}
 *
 * Note: works inplace (pInp == pOut), buffer's length has to be 8*numElmByteArr bytes
 */
/* clang-format on */
IPPCP_INLINE void cp_bytesToBits(const Ipp8u* pInp,
                                 Ipp8u* pOut,
                                 const Ipp32u numElmByteArr,
                                 const Ipp32u outByteSize)
/* clang-format on */
{
    for (Ipp32u i = 0; i < numElmByteArr; i++) {
        Ipp8u C = pInp[i];
        for (Ipp32u j = 0; j < 8; j++) {
            Ipp32u position = (Ipp32u)(IPP_MIN((8 * i + j), outByteSize));
            pOut[position]  = C & 1;
            C >>= 1;
        }
    }
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

    const Ipp32s power = (Ipp32s)1 << d; // 2^{d}
    *out               = (Ipp16u)cp_divAndRoundToNearestInt(power * u, CP_ML_KEM_Q) % power;

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

    const Ipp32s power = (Ipp32s)(1 << d);
    *out               = (Ipp16u)cp_divAndRoundToNearestInt(CP_ML_KEM_Q * (Ipp16s)in, power);

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
#define CP_B_BUFFERSIZE_MAX (256 * CP_D_MAX)
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
IPP_OWN_DEFN(IppStatus,
             cp_byteDecode,
             (Ipp16sPoly * pPolyF, const Ipp16u d, const Ipp8u* B, const int bByteSize))
{
    IPP_BADARG_RET(((d < CP_D_MIN) || (d > CP_D_MAX)), ippStsOutOfRangeErr);
    IPP_BADARG_RET((bByteSize < 32 * d), ippStsOutOfRangeErr);

    Ipp8u b[CP_D_MAX * 8] = { 0 };
    /* Decode byte array to polynomial */
    for (Ipp32u i = 0; i < 256; i++) {
        if ((i & 7) == 0) {
            // Read the next d bytes from B and put 8*d elements in b
            cp_bytesToBits(B, b, d, CP_D_MAX * 8);
            B += d;
        }

        pPolyF->values[i] = 0;
        for (Ipp32u j = 0; j < d; j++) {
            pPolyF->values[i] += b[(i & 7) * d + j] << j;
        }
    }

    return ippStsNoErr;
}

/*
 * Algorithm 8: Takes a seed as input and outputs a pseudorandom sample from the distribution D_{eta}(R_{q}).
 *
 * Input:  pSeed  - byte array B^{64*eta}
 *         eta    - the value of eta, can be 1, 2 or 3
 * Output: pPoly  - array Z_{q}^{256} with values sampled from the distribution D_{eta}(R_{q}).
 *
 */
IPP_OWN_DEFN(IppStatus, cp_samplePolyCBD, (Ipp16sPoly * pPoly, const Ipp8u* pSeed, const Ipp8u eta))
{
    /* Byte array of size 32*eta bytes */
    Ipp8u seedBits[4 * 8 * CP_ML_KEM_ETA_MAX];
    for (Ipp16u i = 0; i < 256; i++) {
        if ((i & 7) == 0) {
            // Read the next 2*eta bytes from pSeed and put 8*2*eta elements in seedBits
            cp_bytesToBits(pSeed, seedBits, 2 * eta, (4 * 8 * CP_ML_KEM_ETA_MAX));
            pSeed += 2 * eta;
        }
        Ipp16s x = 0;
        for (Ipp8u j = 0; j < eta; j++) {
            x += seedBits[2 * (i & 7) * eta + j];
        }
        Ipp16s y = 0;
        for (Ipp8u j = 0; j < eta; j++) {
            y += seedBits[2 * (i & 7) * eta + eta + j];
        }
        // The result will be mapped to the canonical positive representation in the reduction step
        Ipp16s result    = x - y;
        pPoly->values[i] = cp_mlkemBarrettReduce((Ipp32s)result);
    }

    return ippStsNoErr;
}
