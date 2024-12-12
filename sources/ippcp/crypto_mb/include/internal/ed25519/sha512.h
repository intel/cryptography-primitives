/*************************************************************************
* Copyright (C) 2021 Intel Corporation
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
//   Macros and definitions that is necessary for SHA512 computation
*/

#ifndef SHA_512_H
#define SHA_512_H

#include <internal/common/ifma_defs.h>

#if (_MBX >= _MBX_K1)

/* define 64-bit constant */
#if !defined(__GNUC__)
#define CONST_64(x) (x) /*(x##i64)*/
#else
#define CONST_64(x) (x##LL)
#endif

static const int64u sha512_iv[] = { CONST_64(0x6A09E667F3BCC908), CONST_64(0xBB67AE8584CAA73B),
                                    CONST_64(0x3C6EF372FE94F82B), CONST_64(0xA54FF53A5F1D36F1),
                                    CONST_64(0x510E527FADE682D1), CONST_64(0x9B05688C2B3E6C1F),
                                    CONST_64(0x1F83D9ABFB41BD6B), CONST_64(0x5BE0CD19137E2179) };

static __ALIGN64 const int64u sha512_cnt[] = {
    CONST_64(0x428A2F98D728AE22), CONST_64(0x7137449123EF65CD), CONST_64(0xB5C0FBCFEC4D3B2F),
    CONST_64(0xE9B5DBA58189DBBC), CONST_64(0x3956C25BF348B538), CONST_64(0x59F111F1B605D019),
    CONST_64(0x923F82A4AF194F9B), CONST_64(0xAB1C5ED5DA6D8118), CONST_64(0xD807AA98A3030242),
    CONST_64(0x12835B0145706FBE), CONST_64(0x243185BE4EE4B28C), CONST_64(0x550C7DC3D5FFB4E2),
    CONST_64(0x72BE5D74F27B896F), CONST_64(0x80DEB1FE3B1696B1), CONST_64(0x9BDC06A725C71235),
    CONST_64(0xC19BF174CF692694), CONST_64(0xE49B69C19EF14AD2), CONST_64(0xEFBE4786384F25E3),
    CONST_64(0x0FC19DC68B8CD5B5), CONST_64(0x240CA1CC77AC9C65), CONST_64(0x2DE92C6F592B0275),
    CONST_64(0x4A7484AA6EA6E483), CONST_64(0x5CB0A9DCBD41FBD4), CONST_64(0x76F988DA831153B5),
    CONST_64(0x983E5152EE66DFAB), CONST_64(0xA831C66D2DB43210), CONST_64(0xB00327C898FB213F),
    CONST_64(0xBF597FC7BEEF0EE4), CONST_64(0xC6E00BF33DA88FC2), CONST_64(0xD5A79147930AA725),
    CONST_64(0x06CA6351E003826F), CONST_64(0x142929670A0E6E70), CONST_64(0x27B70A8546D22FFC),
    CONST_64(0x2E1B21385C26C926), CONST_64(0x4D2C6DFC5AC42AED), CONST_64(0x53380D139D95B3DF),
    CONST_64(0x650A73548BAF63DE), CONST_64(0x766A0ABB3C77B2A8), CONST_64(0x81C2C92E47EDAEE6),
    CONST_64(0x92722C851482353B), CONST_64(0xA2BFE8A14CF10364), CONST_64(0xA81A664BBC423001),
    CONST_64(0xC24B8B70D0F89791), CONST_64(0xC76C51A30654BE30), CONST_64(0xD192E819D6EF5218),
    CONST_64(0xD69906245565A910), CONST_64(0xF40E35855771202A), CONST_64(0x106AA07032BBD1B8),
    CONST_64(0x19A4C116B8D2D0C8), CONST_64(0x1E376C085141AB53), CONST_64(0x2748774CDF8EEB99),
    CONST_64(0x34B0BCB5E19B48A8), CONST_64(0x391C0CB3C5C95A63), CONST_64(0x4ED8AA4AE3418ACB),
    CONST_64(0x5B9CCA4F7763E373), CONST_64(0x682E6FF3D6B2B8A3), CONST_64(0x748F82EE5DEFB2FC),
    CONST_64(0x78A5636F43172F60), CONST_64(0x84C87814A1F0AB72), CONST_64(0x8CC702081A6439EC),
    CONST_64(0x90BEFFFA23631E28), CONST_64(0xA4506CEBDE82BDE9), CONST_64(0xBEF9A3F7B2C67915),
    CONST_64(0xC67178F2E372532B), CONST_64(0xCA273ECEEA26619C), CONST_64(0xD186B8C721C0C207),
    CONST_64(0xEADA7DD6CDE0EB1E), CONST_64(0xF57D4F7FEE6ED178), CONST_64(0x06F067AA72176FBA),
    CONST_64(0x0A637DC5A2C898A6), CONST_64(0x113F9804BEF90DAE), CONST_64(0x1B710B35131C471B),
    CONST_64(0x28DB77F523047D84), CONST_64(0x32CAAB7B40C72493), CONST_64(0x3C9EBE0A15C9BEBC),
    CONST_64(0x431D67C49C100D4C), CONST_64(0x4CC5D4BECB3E42B6), CONST_64(0x597F299CFC657E2A),
    CONST_64(0x5FCB6FAB3AD6FAEC), CONST_64(0x6C44198C4A475817)
};

/* SHA512 constants */
#define SHA512_DIGEST_BITSIZE 512
#define BYTESIZE              (8)

#define MBS_SHA512 (128)
#define MLR_SHA512 (sizeof(int64u) * 2)

/* Logical Shifts (right and left) of WORD */
#define LSR32(x, nBits) ((x) >> (nBits))
#define LSL32(x, nBits) ((x) << (nBits))

/* Rotate (right and left) of WORD */
#if defined(_MSC_VER) && !defined(__ICL)
#include <stdlib.h>
#define ROR32(x, nBits) _lrotr((x), (nBits))
#define ROL32(x, nBits) _lrotl((x), (nBits))
#else
#define ROR32(x, nBits) (LSR32((x), (nBits)) | LSL32((x), 32 - (nBits)))
#define ROL32(x, nBits) ROR32((x), (32 - (nBits)))
#endif

/* Logical Shifts (right and left) of DWORD */
#define LSR64(x, nBits) ((x) >> (nBits))
#define LSL64(x, nBits) ((x) << (nBits))

/* Rotate (right and left) of DWORD */
#define ROR64(x, nBits) (LSR64((x), (nBits)) | LSL64((x), 64 - (nBits)))
#define ROL64(x, nBits) ROR64((x), (64 - (nBits)))

/* WORD and DWORD manipulators */
#define LODWORD(x)          ((int32u)(x))
#define HIDWORD(x)          ((int32u)(((int64u)(x) >> 32) & 0xFFFFFFFF))
#define MAKEDWORD(wLo, wHi) ((int64u)(((int32u)(wLo)) | ((int64u)((int32u)(wHi))) << 32))

/* Change endian */
#if defined(_MSC_VER)
#define ENDIANNESS(x)   _byteswap_ulong((x))
#define ENDIANNESS32(x) ENDIANNESS((x))
#define ENDIANNESS64(x) _byteswap_uint64((x))
#elif defined(__ICL)
#define ENDIANNESS(x)   _bswap((x))
#define ENDIANNESS32(x) ENDIANNESS((x))
#define ENDIANNESS64(x) _bswap64((x))
#else
#define ENDIANNESS(x)   ((ROR32((x), 24) & 0x00ff00ff) | (ROR32((x), 8) & 0xff00ff00))
#define ENDIANNESS32(x) ENDIANNESS((x))
#define ENDIANNESS64(x) MAKEDWORD(ENDIANNESS(HIDWORD((x))), ENDIANNESS(LODWORD((x))))
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/*
// SHA512 Specific Macros
//
// Note: All operations act on DWORDs (64-bits)
*/

#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SUM0(x) (ROR64((x), 28) ^ ROR64((x), 34) ^ ROR64((x), 39))
#define SUM1(x) (ROR64((x), 14) ^ ROR64((x), 18) ^ ROR64((x), 41))

#define SIG0(x) (ROR64((x), 1) ^ ROR64((x), 8) ^ LSR64((x), 7))
#define SIG1(x) (ROR64((x), 19) ^ ROR64((x), 61) ^ LSR64((x), 6))

#define SHA512_UPDATE(i) \
    wdat[(i) & 15] +=    \
        SIG1(wdat[((i) + 14) & 15]) + wdat[((i) + 9) & 15] + SIG0(wdat[((i) + 1) & 15])

#define SHA512_STEP(i, j)                                                                       \
    v[(7 - (i)) & 7] += ((j) ? SHA512_UPDATE(i) : wdat[(i) & 15]) + SHA512_cnt_loc[(i) + (j)] + \
                        SUM1(v[(4 - (i)) & 7]) +                                                \
                        CH(v[(4 - (i)) & 7], v[(5 - (i)) & 7], v[(6 - (i)) & 7]);               \
    v[(3 - (i)) & 7] += v[(7 - (i)) & 7];                                                       \
    v[(7 - (i)) & 7] +=                                                                         \
        SUM0(v[(0 - (i)) & 7]) + MAJ(v[(0 - (i)) & 7], v[(1 - (i)) & 7], v[(2 - (i)) & 7])


/*
// SHA512 structures and data types
*/

/* SHA512 digest */
typedef int64u DigestSHA512[8];

/* SHA512 context */
struct _cpSHA512 {
    int msgBuffIdx;              /* buffer entry         */
    int64u msgLenLo;             /* message length       */
    int64u msgLenHi;             /* message length       */
    int8u msgBuffer[MBS_SHA512]; /* buffer      */
    DigestSHA512 msgHash;        /* intermediate hash    */
};
typedef struct _cpSHA512 SHA512State;

#define HASH_LENLO(stt)   ((stt)->msgLenLo)
#define HASH_LENHI(stt)   ((stt)->msgLenHi)
#define HASH_VALUE(stt)   ((stt)->msgHash)
#define HASH_BUFFIDX(stt) ((stt)->msgBuffIdx)
#define HASH_BUFF(stt)    ((stt)->msgBuffer)

/*
// SHA512 internal functions
*/

void SHA512MsgDigest(const int8u* pMsg, int len, int8u* pMD);
void SHA512Init(SHA512State* pState);
void SHA512Update(const int8u* pSrc, int len, SHA512State* pState);
void SHA512Final(int8u* pMD, SHA512State* pState);

#endif /* #if (_MBX>=_MBX_K1) */

#endif /* SHA_512_H */
