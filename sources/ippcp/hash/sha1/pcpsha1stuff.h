/*************************************************************************
* Copyright (C) 2002 Intel Corporation
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
//     Digesting message according to SHA1
//
//  Contents:
//        SHA1 methods and constants
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash.h"
#include "hash/pcphash_rmf.h"

#include <assert.h>

#if !defined(_CP_HASH_SHA1)
#define _CP_HASH_SHA1

/* SHA-1 constants */
static const Ipp32u sha1_iv[] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

static __ALIGN16 const Ipp32u sha1_cnt[] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

IPP_OWN_DEFN(static void, sha1_hashInit, (void* pHash))
{
    /* setup initial digest */
    ((Ipp32u*)pHash)[0] = sha1_iv[0];
    ((Ipp32u*)pHash)[1] = sha1_iv[1];
    ((Ipp32u*)pHash)[2] = sha1_iv[2];
    ((Ipp32u*)pHash)[3] = sha1_iv[3];
    ((Ipp32u*)pHash)[4] = sha1_iv[4];
}

IPP_OWN_DEFN(static void, sha1_hashUpdate, (void* pHash, const Ipp8u* pMsg, int msgLen))
{
    UpdateSHA1(pHash, pMsg, msgLen, sha1_cnt);
}

#if (_SHA_NI_ENABLING_ == _FEATURE_TICKTOCK_ || _SHA_NI_ENABLING_ == _FEATURE_ON_)
IPP_OWN_DEFN(static void, sha1_ni_hashUpdate, (void* pHash, const Ipp8u* pMsg, int msgLen))
{
    UpdateSHA1ni(pHash, pMsg, msgLen, sha1_cnt);
}
#endif

IPP_OWN_DEFN(static void, sha1_hashOctString, (Ipp8u * pMD, void* pHashVal, const int hashByteSize))
{
    /* Handle the case when the requested hashByteSize is bigger than supported */
    const int hashMaxByteSize = IPP_SHA1_DIGEST_BITSIZE / 8; /* 20 */
    const int outByteSize     = IPP_MIN(hashByteSize, hashMaxByteSize);

    /* The assertion is needed to indicate the case of incorrect usage of
       the function during the development stage. */
    assert(hashByteSize <= hashMaxByteSize);

    const int numWords    = outByteSize / (int)sizeof(Ipp32u);
    const int numByteTail = outByteSize % (int)sizeof(Ipp32u);

    /* convert hash into big endian */
    for (int i = 0; i < numWords; i++) {
        ((Ipp32u*)pMD)[i] = ENDIANNESS32(((Ipp32u*)pHashVal)[i]);
    }
    if (numByteTail) {
        Ipp32u lastWord = ENDIANNESS32(((Ipp32u*)pHashVal)[numWords]);
        CopyBlock(&lastWord, &pMD[outByteSize - numByteTail], numByteTail);
    }
}

IPP_OWN_DEFN(static void, sha1_msgRep, (Ipp8u * pDst, Ipp64u lenLo, Ipp64u lenHi))
{
    IPP_UNREFERENCED_PARAMETER(lenHi);
    lenLo                = ENDIANNESS64(lenLo << 3);
    ((Ipp64u*)(pDst))[0] = lenLo;
}

#define cpFinalizeSHA1 OWNAPI(cpFinalizeSHA1)
/* clang-format off */
IPP_OWN_DECL(void, cpFinalizeSHA1, (DigestSHA1 pHash,
                                    const Ipp8u* inpBuffer,
                                    int inpLen,
                                    Ipp64u processedMsgLen))
/* clang-format on */
#endif /* #if !defined(_CP_HASH_SHA1) */
