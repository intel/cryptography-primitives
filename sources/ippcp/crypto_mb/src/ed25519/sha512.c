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

#include <internal/ed25519/sha512.h>
#include <internal/common/mem_fns.h>

#if (_MBX >= _MBX_K1)

/* setup init hash value */
static void sha512_init(int64u* pHash)
{
    pHash[0] = sha512_iv[0];
    pHash[1] = sha512_iv[1];
    pHash[2] = sha512_iv[2];
    pHash[3] = sha512_iv[3];
    pHash[4] = sha512_iv[4];
    pHash[5] = sha512_iv[5];
    pHash[6] = sha512_iv[6];
    pHash[7] = sha512_iv[7];
}

static void sha512_update(void* uniHash, const int8u* mblk, int mlen)
{
    int32u* data = (int32u*)mblk;

    int64u* digest         = (int64u*)uniHash;
    int64u* SHA512_cnt_loc = (int64u*)sha512_cnt;

    for (; mlen >= MBS_SHA512; data += MBS_SHA512 / sizeof(int32u), mlen -= MBS_SHA512) {
        int64u wdat[16];
        int j;

        int64u v[8];

        /* initialize the first 16 words in the array W (remember about endian) */
        for (j = 0; j < 16; j++) {
            int32u hiX = data[2 * j];
            int32u loX = data[2 * j + 1];
            wdat[j]    = MAKEDWORD(ENDIANNESS(loX), ENDIANNESS(hiX));
        }

        /* copy digest */
        CopyBlock(digest, v, SHA512_DIGEST_BITSIZE / BYTESIZE);

        for (j = 0; j < 80; j += 16) {
            SHA512_STEP(0, j);
            SHA512_STEP(1, j);
            SHA512_STEP(2, j);
            SHA512_STEP(3, j);
            SHA512_STEP(4, j);
            SHA512_STEP(5, j);
            SHA512_STEP(6, j);
            SHA512_STEP(7, j);
            SHA512_STEP(8, j);
            SHA512_STEP(9, j);
            SHA512_STEP(10, j);
            SHA512_STEP(11, j);
            SHA512_STEP(12, j);
            SHA512_STEP(13, j);
            SHA512_STEP(14, j);
            SHA512_STEP(15, j);
        }

        /* update digest */
        digest[0] += v[0];
        digest[1] += v[1];
        digest[2] += v[2];
        digest[3] += v[3];
        digest[4] += v[4];
        digest[5] += v[5];
        digest[6] += v[6];
        digest[7] += v[7];
    }
}

static void sha512_final(DigestSHA512 pHash,
                         const int8u* inpBuffer,
                         int inpLen,
                         const int64u lenLo,
                         const int64u lenHi)
{
    /* local buffer and its length */
    int8u buffer[MBS_SHA512 * 2];
    int bufferLen = inpLen < (MBS_SHA512 - (int)MLR_SHA512) ? MBS_SHA512 : MBS_SHA512 * 2;

    /* copy rest of message into internal buffer */
    CopyBlock(inpBuffer, buffer, inpLen);

    /* pad message */
    buffer[inpLen++] = 0x80;
    PadBlock(0, buffer + inpLen, (int)(bufferLen - inpLen - (int)MLR_SHA512));

    /* message length representation */
    const int64u beLenHi = ENDIANNESS64(LSL64(lenHi, 3) | LSR64(lenLo, 63 - 3));
    const int64u beLenLo = ENDIANNESS64(LSL64(lenLo, 3));
    CopyBlock(&beLenHi, &buffer[bufferLen - 2 * sizeof(int64u)], sizeof(int64u));
    CopyBlock(&beLenLo, &buffer[bufferLen - 1 * sizeof(int64u)], sizeof(int64u));

    /* complete hash computation */
    sha512_update(pHash, buffer, bufferLen);
}


void SHA512Init(SHA512State* pState)
{
    /* zeros message length */
    HASH_LENLO(pState) = 0;
    HASH_LENHI(pState) = 0;
    /* message buffer is free */
    HASH_BUFFIDX(pState) = 0;
    /* clear ctx buffer */
    PadBlock(0, HASH_BUFF(pState), MBS_SHA512);

    /* setup initial digest */
    sha512_init(HASH_VALUE(pState));
}

void SHA512Update(const int8u* pSrc, int len, SHA512State* pState)
{

    /*
// handle non empty message
*/
    if (len) {
        int procLen;

        int idx        = HASH_BUFFIDX(pState);
        int8u* pBuffer = HASH_BUFF(pState);
        int64u lenLo   = HASH_LENLO(pState) + (int64u)len;
        int64u lenHi   = HASH_LENHI(pState);
        if (lenLo < HASH_LENLO(pState))
            lenHi++;

        /* if non empty internal buffer filling */
        if (idx) {
            /* copy from input stream to the internal buffer as match as possible */
            procLen = MIN(len, (MBS_SHA512 - idx));
            CopyBlock(pSrc, pBuffer + idx, procLen);

            /* update message pointer and length */
            pSrc += procLen;
            len -= procLen;
            idx += procLen;

            /* update digest if buffer full */
            if (MBS_SHA512 == idx) {
                sha512_update(HASH_VALUE(pState), pBuffer, MBS_SHA512);
                idx = 0;
            }
        }

        /* main message part processing */
        procLen = len & ~(MBS_SHA512 - 1);
        if (procLen) {
            sha512_update(HASH_VALUE(pState), pSrc, procLen);
            pSrc += procLen;
            len -= procLen;
        }

        /* store rest of message into the internal buffer */
        if (len) {
            CopyBlock(pSrc, pBuffer, len);
            idx += len;
        }

        /* update length of processed message */
        HASH_LENLO(pState)   = lenLo;
        HASH_LENHI(pState)   = lenHi;
        HASH_BUFFIDX(pState) = idx;
    }
}

void SHA512Final(int8u* pMD, SHA512State* pState)
{
    sha512_final(HASH_VALUE(pState),
                 HASH_BUFF(pState),
                 HASH_BUFFIDX(pState),
                 HASH_LENLO(pState),
                 HASH_LENHI(pState));
    /* convert hash into big endian */
    ((int64u*)pMD)[0] = ENDIANNESS64(HASH_VALUE(pState)[0]);
    ((int64u*)pMD)[1] = ENDIANNESS64(HASH_VALUE(pState)[1]);
    ((int64u*)pMD)[2] = ENDIANNESS64(HASH_VALUE(pState)[2]);
    ((int64u*)pMD)[3] = ENDIANNESS64(HASH_VALUE(pState)[3]);
    ((int64u*)pMD)[4] = ENDIANNESS64(HASH_VALUE(pState)[4]);
    ((int64u*)pMD)[5] = ENDIANNESS64(HASH_VALUE(pState)[5]);
    ((int64u*)pMD)[6] = ENDIANNESS64(HASH_VALUE(pState)[6]);
    ((int64u*)pMD)[7] = ENDIANNESS64(HASH_VALUE(pState)[7]);

    /* re-init hash value */
    SHA512Init(pState);
}

void SHA512MsgDigest(const int8u* pMsg, int len, int8u* pMD)
{
    /* message length in the multiple MBS and the rest */
    int msgLenBlks = len & (-MBS_SHA512);
    int msgLenRest = len - msgLenBlks;
    DigestSHA512 hash;

    /* init hash */
    sha512_init(hash);

    /* process main part of the message */
    if (msgLenBlks) {
        sha512_update(hash, pMsg, msgLenBlks);
        pMsg += msgLenBlks;
    }

    sha512_final(hash, pMsg, msgLenRest, (int64u)len, 0);
    hash[0] = ENDIANNESS64(hash[0]);
    hash[1] = ENDIANNESS64(hash[1]);
    hash[2] = ENDIANNESS64(hash[2]);
    hash[3] = ENDIANNESS64(hash[3]);
    hash[4] = ENDIANNESS64(hash[4]);
    hash[5] = ENDIANNESS64(hash[5]);
    hash[6] = ENDIANNESS64(hash[6]);
    hash[7] = ENDIANNESS64(hash[7]);

    CopyBlock(hash, pMD, SHA512_DIGEST_BITSIZE / BYTESIZE);
}

#endif /* #if (_MBX>=_MBX_K1) */
