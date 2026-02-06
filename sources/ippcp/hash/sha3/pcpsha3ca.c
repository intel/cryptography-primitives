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
#include <assert.h>


// FIPS PUB 202 - SHA3 Standard, Algorithm 5: rc(t)
__ALIGN64 static const Ipp64u KECCAK_ROUND_CONSTANTS[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Left-rotates a 64-bit lane by a specified amount
IPPCP_INLINE Ipp64u cp_rotl64(Ipp64u lane, Ipp64u bits)
{
    assert((0 < bits) && (bits < 64));

    return (lane << bits) | (lane >> (64 - bits));
}

IPP_OWN_DEFN(void, cp_keccak_kernel, (Ipp64u state[5 * 5]))
{
    // use registers and spilling as necessary
    Ipp64u lane0  = state[0];
    Ipp64u lane1  = state[1];
    Ipp64u lane2  = state[2];
    Ipp64u lane3  = state[3];
    Ipp64u lane4  = state[4];
    Ipp64u lane5  = state[5];
    Ipp64u lane6  = state[6];
    Ipp64u lane7  = state[7];
    Ipp64u lane8  = state[8];
    Ipp64u lane9  = state[9];
    Ipp64u lane10 = state[10];
    Ipp64u lane11 = state[11];
    Ipp64u lane12 = state[12];
    Ipp64u lane13 = state[13];
    Ipp64u lane14 = state[14];
    Ipp64u lane15 = state[15];
    Ipp64u lane16 = state[16];
    Ipp64u lane17 = state[17];
    Ipp64u lane18 = state[18];
    Ipp64u lane19 = state[19];
    Ipp64u lane20 = state[20];
    Ipp64u lane21 = state[21];
    Ipp64u lane22 = state[22];
    Ipp64u lane23 = state[23];
    Ipp64u lane24 = state[24];

    for (int round = 0; round < KECCAK_ROUNDS; round++) {

        ////////////////////
        // Lane numbering //
        ////////////////////
        // 13 14 10 11 12 //
        //  8  9  5  6  7 //
        //  3  4  0  1  2 //
        // 23 24 20 21 22 //
        // 18 19 15 16 17 //
        ////////////////////

        // FIPS PUB 202 - SHA-3 Standard, 3.2.1 Specification of theta
        const Ipp64u sheet0 = lane0 ^ lane5 ^ lane10 ^ lane15 ^ lane20;
        const Ipp64u sheet1 = lane1 ^ lane6 ^ lane11 ^ lane16 ^ lane21;
        const Ipp64u sheet2 = lane2 ^ lane7 ^ lane12 ^ lane17 ^ lane22;
        const Ipp64u sheet3 = lane3 ^ lane8 ^ lane13 ^ lane18 ^ lane23;
        const Ipp64u sheet4 = lane4 ^ lane9 ^ lane14 ^ lane19 ^ lane24;

        // xorN is applied to lane in sheetN
        const Ipp64u xor0 = sheet4 ^ cp_rotl64(sheet1, 1);
        const Ipp64u xor1 = sheet0 ^ cp_rotl64(sheet2, 1);
        const Ipp64u xor2 = sheet1 ^ cp_rotl64(sheet3, 1);
        const Ipp64u xor3 = sheet2 ^ cp_rotl64(sheet4, 1);
        const Ipp64u xor4 = sheet3 ^ cp_rotl64(sheet0, 1);

        lane0 = lane0 ^ xor0;
        lane1 = lane1 ^ xor1;
        lane2 = lane2 ^ xor2;
        lane3 = lane3 ^ xor3;
        lane4 = lane4 ^ xor4;

        lane5 = lane5 ^ xor0;
        lane6 = lane6 ^ xor1;
        lane7 = lane7 ^ xor2;
        lane8 = lane8 ^ xor3;
        lane9 = lane9 ^ xor4;

        lane10 = lane10 ^ xor0;
        lane11 = lane11 ^ xor1;
        lane12 = lane12 ^ xor2;
        lane13 = lane13 ^ xor3;
        lane14 = lane14 ^ xor4;

        lane15 = lane15 ^ xor0;
        lane16 = lane16 ^ xor1;
        lane17 = lane17 ^ xor2;
        lane18 = lane18 ^ xor3;
        lane19 = lane19 ^ xor4;

        lane20 = lane20 ^ xor0;
        lane21 = lane21 ^ xor1;
        lane22 = lane22 ^ xor2;
        lane23 = lane23 ^ xor3;
        lane24 = lane24 ^ xor4;

        // FIPS PUB 202 - SHA-3 Standard, 3.2.2 Specification of rho
        // Indices are the values of "Table 2: Offsets of rho" mod 64
        lane1  = cp_rotl64(lane1, 1);
        lane2  = cp_rotl64(lane2, 62);
        lane3  = cp_rotl64(lane3, 28);
        lane4  = cp_rotl64(lane4, 27);
        lane5  = cp_rotl64(lane5, 36);
        lane6  = cp_rotl64(lane6, 44);
        lane7  = cp_rotl64(lane7, 6);
        lane8  = cp_rotl64(lane8, 55);
        lane9  = cp_rotl64(lane9, 20);
        lane10 = cp_rotl64(lane10, 3);
        lane11 = cp_rotl64(lane11, 10);
        lane12 = cp_rotl64(lane12, 43);
        lane13 = cp_rotl64(lane13, 25);
        lane14 = cp_rotl64(lane14, 39);
        lane15 = cp_rotl64(lane15, 41);
        lane16 = cp_rotl64(lane16, 45);
        lane17 = cp_rotl64(lane17, 15);
        lane18 = cp_rotl64(lane18, 21);
        lane19 = cp_rotl64(lane19, 8);
        lane20 = cp_rotl64(lane20, 18);
        lane21 = cp_rotl64(lane21, 2);
        lane22 = cp_rotl64(lane22, 61);
        lane23 = cp_rotl64(lane23, 56);
        lane24 = cp_rotl64(lane24, 14);

        // simplify dependencies in the next steps
        const Ipp64u copy0  = lane0;
        const Ipp64u copy1  = lane1;
        const Ipp64u copy2  = lane2;
        const Ipp64u copy3  = lane3;
        const Ipp64u copy4  = lane4;
        const Ipp64u copy5  = lane5;
        const Ipp64u copy6  = lane6;
        const Ipp64u copy7  = lane7;
        const Ipp64u copy8  = lane8;
        const Ipp64u copy9  = lane9;
        const Ipp64u copy10 = lane10;
        const Ipp64u copy11 = lane11;
        const Ipp64u copy12 = lane12;
        const Ipp64u copy13 = lane13;
        const Ipp64u copy14 = lane14;
        const Ipp64u copy15 = lane15;
        const Ipp64u copy16 = lane16;
        const Ipp64u copy17 = lane17;
        const Ipp64u copy18 = lane18;
        const Ipp64u copy19 = lane19;
        const Ipp64u copy20 = lane20;
        const Ipp64u copy21 = lane21;
        const Ipp64u copy22 = lane22;
        const Ipp64u copy23 = lane23;
        const Ipp64u copy24 = lane24;

        // FIPS PUB 202 - SHA-3 Standard, 3.2.3 Specification of pi
        // FIPS PUB 202 - SHA-3 Standard, 3.2.4 Specification of chi
        // FIPS PUB 202 - SHA-3 Standard, 3.2.5 Specification of iota
        // merge pi chi and iota
        /* clang-format off */
        lane0  = copy0  ^ ((~copy6 ) & copy12) ^ KECCAK_ROUND_CONSTANTS[round];
        lane1  = copy6  ^ ((~copy12) & copy18);
        lane2  = copy12 ^ ((~copy18) & copy24);
        lane3  = copy18 ^ ((~copy24) & copy0 );
        lane4  = copy24 ^ ((~copy0 ) & copy6 );

        lane5  = copy3  ^ ((~copy9 ) & copy10);
        lane6  = copy9  ^ ((~copy10) & copy16);
        lane7  = copy10 ^ ((~copy16) & copy22);
        lane8  = copy16 ^ ((~copy22) & copy3 );
        lane9  = copy22 ^ ((~copy3 ) & copy9 );

        lane10 = copy1  ^ ((~copy7 ) & copy13);
        lane11 = copy7  ^ ((~copy13) & copy19);
        lane12 = copy13 ^ ((~copy19) & copy20);
        lane13 = copy19 ^ ((~copy20) & copy1 );
        lane14 = copy20 ^ ((~copy1 ) & copy7 );

        lane15 = copy4  ^ ((~copy5 ) & copy11);
        lane16 = copy5  ^ ((~copy11) & copy17);
        lane17 = copy11 ^ ((~copy17) & copy23);
        lane18 = copy17 ^ ((~copy23) & copy4 );
        lane19 = copy23 ^ ((~copy4 ) & copy5 );

        lane20 = copy2  ^ ((~copy8 ) & copy14);
        lane21 = copy8  ^ ((~copy14) & copy15);
        lane22 = copy14 ^ ((~copy15) & copy21);
        lane23 = copy15 ^ ((~copy21) & copy2 );
        lane24 = copy21 ^ ((~copy2 ) & copy8 );
        /* clang-format on */
    }

    state[0]  = lane0;
    state[1]  = lane1;
    state[2]  = lane2;
    state[3]  = lane3;
    state[4]  = lane4;
    state[5]  = lane5;
    state[6]  = lane6;
    state[7]  = lane7;
    state[8]  = lane8;
    state[9]  = lane9;
    state[10] = lane10;
    state[11] = lane11;
    state[12] = lane12;
    state[13] = lane13;
    state[14] = lane14;
    state[15] = lane15;
    state[16] = lane16;
    state[17] = lane17;
    state[18] = lane18;
    state[19] = lane19;
    state[20] = lane20;
    state[21] = lane21;
    state[22] = lane22;
    state[23] = lane23;
    state[24] = lane24;
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
