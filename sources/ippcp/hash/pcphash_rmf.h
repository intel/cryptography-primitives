/*************************************************************************
* Copyright (C) 2016 Intel Corporation
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
//  Purpose:
//     Cryptography Primitive.
//     Security Hash Standard
//     Internal Definitions and Internal Functions Prototypes
//
*/

#if !defined(_CP_HASH_RMF_H)
#define _CP_HASH_RMF_H

#include "hash/pcphash.h"
#include "hash/pcphashmethod_rmf.h"
#include "hash/sha3/sha3_stuff.h"

#define HASH_STATE_RMF_SIZE (sizeof(IppsHashState_rmf))

/* size of the context in bytes */
#define SHA1_CONTEXT_SIZE     (HASH_STATE_RMF_SIZE + MBS_SHA1 + IPP_SHA1_STATE_BYTESIZE)
#define SHA224_CONTEXT_SIZE   (HASH_STATE_RMF_SIZE + MBS_SHA224 + IPP_SHA224_STATE_BYTESIZE)
#define SHA256_CONTEXT_SIZE   (HASH_STATE_RMF_SIZE + MBS_SHA256 + IPP_SHA256_STATE_BYTESIZE)
#define SHA384_CONTEXT_SIZE   (HASH_STATE_RMF_SIZE + MBS_SHA384 + IPP_SHA384_STATE_BYTESIZE)
#define SHA512_CONTEXT_SIZE   (HASH_STATE_RMF_SIZE + MBS_SHA512 + IPP_SHA512_STATE_BYTESIZE)
#define MD5_CONTEXT_SIZE      (HASH_STATE_RMF_SIZE + MBS_MD5 + IPP_MD5_STATE_BYTESIZE)
#define SM3_CONTEXT_SIZE      (HASH_STATE_RMF_SIZE + MBS_SM3 + IPP_SM3_STATE_BYTESIZE)
#define SHA3_224_CONTEXT_SIZE (HASH_STATE_RMF_SIZE + MBS_SHA3_224 + IPP_SHA3_STATE_BYTESIZE)
#define SHA3_256_CONTEXT_SIZE (HASH_STATE_RMF_SIZE + MBS_SHA3_256 + IPP_SHA3_STATE_BYTESIZE)
#define SHA3_384_CONTEXT_SIZE (HASH_STATE_RMF_SIZE + MBS_SHA3_384 + IPP_SHA3_STATE_BYTESIZE)
#define SHA3_512_CONTEXT_SIZE (HASH_STATE_RMF_SIZE + MBS_SHA3_512 + IPP_SHA3_STATE_BYTESIZE)
#define SHAKE128_CONTEXT_SIZE (HASH_STATE_RMF_SIZE + MBS_SHAKE128 + IPP_SHA3_STATE_BYTESIZE)
#define SHAKE256_CONTEXT_SIZE (HASH_STATE_RMF_SIZE + MBS_SHAKE256 + IPP_SHA3_STATE_BYTESIZE)

#define MAX_HASH_RMF_CONTEXT_SIZE (SHAKE128_CONTEXT_SIZE)

/* integer number N that is used to determine the size of IppsHashState_rmf[N] array */
#define CONTEXT_HASH_RMF_ARRAY_SIZE (MAX_HASH_RMF_CONTEXT_SIZE / HASH_STATE_RMF_SIZE + 1)

/*
 * HashProcessState enumeration helps to track the hashing functions' sequence of calls.
 *
 *  Rules and restrictions for calls:
 *    1. ippsHashInit_rmf() can be called at any time.
 *    2. ippsHashUpdate_rmf() can be called at any time, but not after ippsHashSqueeze_rmf().
 *    3. ippsHashSqueeze_rmf() can be called at any time.
 *    4. ippsHashFinal_rmf() can be called at any time, but not after ippsHashSqueeze_rmf().
 *    5. ippsHashGetTag_rmf() can be called at any time, but not after ippsHashSqueeze_rmf().
 */
typedef enum { HashInit, HashProcess, HashFinal, HashSqueeze } HashProcessState;

struct _cpHashCtx_rmf {
    Ipp32u idCtx;                    /*                  hash identifier                  */
    HashProcessState processState;   /*                hash state machine                 */
    const cpHashMethod_rmf* pMethod; /*                   hash methods                    */
    int msgBuffIdx;                  /*                   buffer index                    */
    int digestLenProcessed;          /* length of the hash that has already been squeezed */
    Ipp64u msgLenLo;                 /*                 processed message                 */
    Ipp64u msgLenHi;                 /*                  length (bytes)                   */
    Ipp8u* msgBuffer;                /*                      buffer                       */
    Ipp64u* msgHash;                 /*                    hash value                     */

    /*
    *    memory that stores buffer, pointed by msgBuffer
    *                                ...
    *    memory that stores an intermediate hash value, pointed by msgHash
    *                                ...
    */
};

/* accessors (see others in pcphash.h) */
#define HASH_METHOD(stt)   ((stt)->pMethod)
#define HASH_STATE(stt)    ((stt)->processState)
#define HASH_SQUEEZED(stt) ((stt)->digestLenProcessed)

/* setup pointers to buffer and hash */
#define HASH_SETUP_POINTERS(stt)                                  \
    (stt)->msgBuffer = (Ipp8u*)(stt) + sizeof(IppsHashState_rmf); \
    (stt)->msgHash =                                              \
        (Ipp64u*)((Ipp8u*)(stt) + sizeof(IppsHashState_rmf) + (stt)->pMethod->msgBlkSize)

#define cpFinalize_rmf OWNAPI(cpFinalize_rmf)
/* clang-format off */
IPP_OWN_DECL(void, cpFinalize_rmf, (DigestSHA512 pHash,
                                    const Ipp8u* inpBuffer,
                                    int inpLen,
                                    Ipp64u lenLo,
                                    Ipp64u lenHi,
                                    const IppsHashMethod* method))
/* clang-format on */

/* calculates the rest of hash if any and put it to user's buffer
*  can squeeze hash by parts
*  digestLen - (input) size of hash that will be squeezed (in bytes)
*  digestLenProcessed - (input/output) size of hash that was already squeezed (in bytes)
*  digestLenProcessed < pMethod->msgBlkSize
*/
void static cpHashSqueeze(Ipp8u* pMD,
                          Ipp64u* hash,
                          const IppsHashMethod* pMethod,
                          const int digestLen,
                          int* const digestLenProcessed)
{
    int _digestLen   = digestLen;
    Ipp8u* pMD_tmp   = pMD;
    Ipp64u* hash_tmp = (Ipp64u*)((Ipp8u*)(hash) + *digestLenProcessed);
    int msgBlkSize   = pMethod->msgBlkSize - *digestLenProcessed;

    *digestLenProcessed += _digestLen;
    if (*digestLenProcessed > pMethod->msgBlkSize) {
        *digestLenProcessed -= pMethod->msgBlkSize;
    }

    pMethod->hashOctStr(pMD_tmp, hash_tmp, IPP_MIN(_digestLen, msgBlkSize));
    pMD_tmp += IPP_MIN(_digestLen, msgBlkSize);
    _digestLen -= msgBlkSize;

    if (cpIsSHAKEAlgID(pMethod->hashAlgId)) {
        while (_digestLen > 0) {
            cp_keccak_kernel(hash);
            msgBlkSize = pMethod->msgBlkSize;
            pMethod->hashOctStr(pMD_tmp, hash, IPP_MIN(_digestLen, msgBlkSize));
            pMD_tmp += IPP_MIN(_digestLen, msgBlkSize);
            _digestLen -= msgBlkSize;
        }
    }
}

#endif /* _CP_HASH_RMF_H */
