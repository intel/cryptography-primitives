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
//
//  Purpose:
//     Cryptography Primitive.
//     Security Hash Standard
//     Generalized Functionality
//
//  Contents:
//     cpFinalize_rmf()
//
*/

#include "owndefs.h"
#include "owncp.h"
#include "hash/pcphash_rmf.h"
#include "pcptool.h"

/* clang-format off */
IPP_OWN_DEFN(void, cpFinalize_rmf, (DigestSHA512 pHash,
                                    const Ipp8u* inpBuffer,
                                    int inpLen,
                                    Ipp64u lenLo,
                                    Ipp64u lenHi,
                                    const IppsHashMethod* method))
/* clang-format on */
{
    int mbs            = method->msgBlkSize;    /* message block size */
    int mrl            = method->msgLenRepSize; /* processed length representation size */
    IppHashAlgId algid = method->hashAlgId;

    /* local buffer and it length */
    Ipp8u buffer[MBS_HASH_MAX * 2];
    int bufferLen = inpLen < (mbs - mrl) ? mbs : mbs * 2;

    // Path for sha3 algorithms
    if (algid == ippHashAlg_SHA3_224 || algid == ippHashAlg_SHA3_256 ||
        algid == ippHashAlg_SHA3_384 || algid == ippHashAlg_SHA3_512) {
        /* copy rest of message into internal buffer */
        PadBlock(0, buffer, bufferLen);
        CopyBlock(inpBuffer, buffer, inpLen);

        buffer[inpLen] ^= 0x06;
        buffer[mbs - 1] ^= 0x80;
    } else if (cpIsSHAKEAlgID(algid)) {
        PadBlock(0, buffer, bufferLen);
        CopyBlock(inpBuffer, buffer, inpLen);
        buffer[inpLen] ^= 0x1F;
        buffer[mbs - 1] ^= 0x80;
    }

    // Path for not sha3 algorithms
    else {
        /* copy rest of message into internal buffer */
        CopyBlock(inpBuffer, buffer, inpLen);
        /* pad message */
        buffer[inpLen++] = 0x80;
        PadBlock(0, buffer + inpLen, bufferLen - inpLen - mrl);

        /* message length representation */
        method->msgLenRep(buffer + bufferLen - mrl, lenLo, lenHi);
    }

    /* complete hash computation */
    method->hashUpdate(pHash, buffer, bufferLen);

    // zeroization
    PurgeBlock(buffer, bufferLen);
}
