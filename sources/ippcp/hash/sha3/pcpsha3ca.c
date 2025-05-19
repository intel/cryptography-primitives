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
//
//  Purpose:
//     Cryptography Primitive.
//     SHA3 Family General Functionality
//
//  Contents:
//     cp_keccak_kernel()
//     cpUpdateSHA3()
//     cp_sha3_hashInit()
//     cp_sha3_hashOctString()
//
*/

#include "hash/sha3/sha3_stuff.h"

// FIPS PUB 202 - SHA3 Standard, Algorithm 5: rc(t)
static const Ipp64u KECCAK_ROUND_CONSTANTS[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// FIPS PUB 202 - SHA-3 Standard, Table 2: Offsets of rho
// Table is rotated to have lane=0 (x=0,y=0) in the top-left corner
// Being rotations, they must be considered `mod 64`
/* clang-format off */
static const Ipp64u KECCAK_RHO_OFFSETS[5 * 5] = {
      0,   1, 190,  28,  91,
     36, 300,   6,  55, 276,
      3,  10, 171, 153, 231,
    105,  45,  15,  21, 136,
    210,  66, 253, 120,  78,
};
/* clang-format on */

// Left-rotates a 64-bit lane by a specified amount
__IPPCP_INLINE Ipp64u cp_rotl64(Ipp64u lane, Ipp64u bits)
{
    // reduce rotation to max 63 bits to avoid losing bits
    bits %= 64;

    return (lane << bits) | (lane >> (64 - bits));
}

IPP_OWN_DEFN(void, cp_keccak_kernel, (Ipp64u state[5 * 5]))
{

    for (int round = 0; round < KECCAK_ROUNDS; round++) {

        // FIPS PUB 202 - SHA-3 Standard, 3.2.1 Specification of theta
        {
            // precompute xor over sheets and save them temporarily
            // before making any updates to the lanes in the 2nd half of the step
            Ipp64u sheet_xor[5]; // 5 sheets in total
            for (int i = 0; i < 5; i++) {
                // lane indices belonging to a common sheet differ by the same amount, 5
                sheet_xor[i] =
                    state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            }

            for (int i = 0; i < (5 * 5); i++) {
                Ipp64u sheet_before        = sheet_xor[(i - 1 + 5) % 5];
                Ipp64u sheet_after         = sheet_xor[(i + 1) % 5];
                Ipp64u rotated_sheet_after = cp_rotl64(sheet_after, 1);

                state[i] = state[i] ^ sheet_before ^ rotated_sheet_after;
            }
        }

        // FIPS PUB 202 - SHA-3 Standard, 3.2.2 Specification of rho
        for (int i = 0; i < (5 * 5); i++) {
            state[i] = cp_rotl64(state[i], KECCAK_RHO_OFFSETS[i]);
        }

        // FIPS PUB 202 - SHA-3 Standard, 3.2.3 Specification of pi
        {
            Ipp64u new_state[5 * 5];

#define STATE_X_Y_to_IDX(x, y) ((x) + 5 * (y))

            // Step 1
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int src_index  = STATE_X_Y_to_IDX((x + 3 * y) % 5, x);
                    int dest_index = STATE_X_Y_to_IDX(x, y);

                    new_state[dest_index] = state[src_index];
                }
            }

            // Step 2
            for (int i = 0; i < (5 * 5); i++) {
                state[i] = new_state[i];
            }
        }

        // FIPS PUB 202 - SHA-3 Standard, 3.2.4 Specification of chi
        {
            Ipp64u new_state[5 * 5];

            // Step 1
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int dest_index = STATE_X_Y_to_IDX(x, y);

                    int src1_index = STATE_X_Y_to_IDX((x + 1) % 5, y);
                    int src2_index = STATE_X_Y_to_IDX((x + 2) % 5, y);

                    new_state[dest_index] =
                        state[dest_index] ^
                        ((state[src1_index] ^ 0xFFFFFFFFFFFFFFFF) // bit negation along the lane
                         & state[src2_index]);
                }
            }

            // Step 2
            for (int i = 0; i < (5 * 5); i++) {
                state[i] = new_state[i];
            }
        }

        // FIPS PUB 202 - SHA-3 Standard, 3.2.5 Specification of iota
        state[0] ^= KECCAK_ROUND_CONSTANTS[round];
    }
}

IPP_OWN_DEFN(void, cpUpdateSHA3, (void* uniHash, const Ipp8u* mblk, int mlen, const void* pParam))
{
    int i;
    int* block_size = (int*)pParam;

    while (mlen >= *block_size) {
        for (i = 0; i < *block_size / 8; i++) {
            ((Ipp64u*)uniHash)[i] ^= ((Ipp64u*)mblk)[i];
        }
        cp_keccak_kernel(uniHash);
        mblk += *block_size;
        mlen -= *block_size;
    }
}

IPP_OWN_DEFN(void, cp_sha3_hashInit, (void* pHash)) { PadBlock(0, pHash, IPP_SHA3_STATE_BYTESIZE); }

/* cut hash */
IPP_OWN_DEFN(void, cp_sha3_hashOctString, (Ipp8u * pMD, void* pHashVal, const int hashSize))
{
    CopyBlock(pHashVal, pMD, hashSize);
}
