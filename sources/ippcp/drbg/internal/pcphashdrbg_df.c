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

/*
 * Hashes input strings and returns the requested number of bits
 *
 * Input parameters:
 *  Pointers to the strings that are hashed to get seed material:
 *    inputParam1            input string 1 (a non NULL value)
 *    inputParam2            optional input string (can be NULL)
 *    inputParam3            optional input string (can be NULL)
 *  inputParam1Len         inputParam1 length in bits
 *  inputParam2Len         inputParam2 length in bits (can be zero)
 *  inputParam3Len         inputParam3 length in bits (can be zero)
 *  nBitsToReturn          length of requestedBits string
 *  pDrbgCtx               pointer to the DRBG state
 *
 * Output parameters:
 *  requestedBits          resulted string (V or C) that contains secret values
 *
 * NIST.SP.800-90Ar1 Section 10.3.1 Derivation Function Using a Hash Function (Hash_df)
 *
 * Hash_df Process:
 *     temp = NULL
 *     len = [no_of_bits_to_return / outlen]
 *     counter = 0x01
 *     For (i = 1 to len) {
 *         temp = temp || Hash (counter || no_of_bits_to_return || input_string)
 *         counter = counter + 1
 *     requested_bits = leftmost (temp, no_of_bits_to_return)
 *     Return (SUCCESS, requested_bits)
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpbn.h"
#include "pcptool.h"
#include "drbg/pcphashdrbg.h"
#include "hash/pcphash_rmf.h"

IPP_OWN_DEFN(IppStatus,
             cpHashDRBG_df,
             (const Ipp8u* inputParam1,
              const int inputParam1Len,
              const Ipp8u* inputParam2,
              const int inputParam2Len,
              const Ipp8u* inputParam3,
              const int inputParam3Len,
              Ipp8u* requestedBits,
              const int nBitsToReturn,
              IppsHashDRBGState* pDrbgCtx))
{
    /* The maximum length (max_number_of_bits) is implementation dependent,
       but *shall* be less than or equal to (255 × outlen)
       (outlen is Output Block Length or digest bit size) */
    if (nBitsToReturn > 255 * pDrbgCtx->pHashMethod->hashLen * BYTESIZE) {
        return ippStsOutOfRangeErr;
    }

    IppStatus sts = ippStsNoErr;

    Ipp8u* pOutput = requestedBits;

    Ipp8u counter = 1; /* An 8-bit binary value representing the integer "1" */
    Ipp8u bitsToReturn[4];

    /* present an 32-bit unsigned int in BE format */
    bitsToReturn[0] = (Ipp8u)((nBitsToReturn >> 24) & 0xFF);
    bitsToReturn[1] = (Ipp8u)((nBitsToReturn >> 16) & 0xFF);
    bitsToReturn[2] = (Ipp8u)((nBitsToReturn >> 8) & 0xFF);
    bitsToReturn[3] = (Ipp8u)(nBitsToReturn & 0xFF);

    /*
        For i = 1 to len do
        // no_of_bits_to_return is used as a 32-bit string
        temp = temp || Hash (counter || no_of_bits_to_return || input_msg)
        counter = counter + 1
    */

    int outputHashBufLen = pDrbgCtx->pHashMethod->hashLen;

    int residual = BITS2WORD8_SIZE(nBitsToReturn);
    while (residual > 0) {
        /* counter || no_of_bits_to_return || input_msg */
        sts = ippsHashInit_rmf(pDrbgCtx->hashState, pDrbgCtx->pHashMethod);
        sts |= ippsHashUpdate_rmf(&counter, sizeof(counter), pDrbgCtx->hashState);
        sts |= ippsHashUpdate_rmf(bitsToReturn, sizeof(bitsToReturn), pDrbgCtx->hashState);
        sts |=
            ippsHashUpdate_rmf(inputParam1, BITS2WORD8_SIZE(inputParam1Len), pDrbgCtx->hashState);
        if (inputParam2Len) {
            sts |= ippsHashUpdate_rmf(inputParam2,
                                      BITS2WORD8_SIZE(inputParam2Len),
                                      pDrbgCtx->hashState);
        }
        if (inputParam3Len) {
            sts |= ippsHashUpdate_rmf(inputParam3,
                                      BITS2WORD8_SIZE(inputParam3Len),
                                      pDrbgCtx->hashState);
        }
        sts |= ippsHashFinal_rmf(pDrbgCtx->hashOutputBuf, pDrbgCtx->hashState);
        if (ippStsNoErr != sts) {
            /* zeroize requestedBits */
            PurgeBlock((void*)pOutput, BITS2WORD8_SIZE(nBitsToReturn));
            return ippStsHashOperationErr;
        }

        COPY_BNU(pOutput, pDrbgCtx->hashOutputBuf, IPP_MIN(residual, outputHashBufLen));

        counter++;
        pOutput += IPP_MIN(residual, outputHashBufLen);
        residual -= outputHashBufLen;
    }

    /* zeroize Hash DRBG hashState */
    PurgeBlock((void*)pDrbgCtx->hashState, HASH_DRBG_HASH_STATE_SIZE(pDrbgCtx));

    return ippStsNoErr;
}
