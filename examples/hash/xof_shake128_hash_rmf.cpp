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

/*!
  *
  *  \file
  *
  *  \brief XOF Hash example
  *
  *  This example demonstrates usage of Hash algorithms to digest a message with extendable output length.
  *  Reduced Memory Footprint (_rmf) API is used in this example.
  *
  */

#include <string.h>
#include <vector>

#include "ippcp.h"
#include "examples_common.h"

/* Message text */
const Ipp8u msg[] = "abc";

/* Known digest to check the results (189 bytes)*/
const Ipp8u shake128[] = "\x58\x81\x09\x2d\xd8\x18\xbf\x5c\xf8\xa3\xdd\xb7\x93\xfb\xcb\xa7\x40\x97"
                         "\xd5\xc5\x26\xa6\xd3\x5f\x97"
                         "\xb8\x33\x51\x94\x0f\x2c\xc8\x44\xc5\x0a\xf3\x2a\xcd\x3f\x2c\xdd\x06\x65"
                         "\x68\x70\x6f\x50\x9b\xc1\xbd"
                         "\xde\x58\x29\x5d\xae\x3f\x89\x1a\x9a\x0f\xca\x57\x83\x78\x9a\x41\xf8\x61"
                         "\x12\x14\xce\x61\x23\x94\xdf"
                         "\x28\x6a\x62\xd1\xa2\x25\x2a\xa9\x4d\xb9\xc5\x38\x95\x6c\x71\x7d\xc2\xbe"
                         "\xd4\xf2\x32\xa0\x29\x4c\x85"
                         "\x7c\x73\x0a\xa1\x60\x67\xac\x10\x62\xf1\x20\x1f\xb0\xd3\x77\xcf\xb9\xcd"
                         "\xe4\xc6\x35\x99\xb2\x7f\x34"
                         "\x62\xbb\xa4\xa0\xed\x29\x6c\x80\x1f\x9f\xf7\xf5\x73\x02\xbb\x30\x76\xee"
                         "\x14\x5f\x97\xa3\x2a\xe6\x8e"
                         "\x76\xab\x66\xc4\x8d\x51\x67\x5b\xd4\x9a\xcc\x29\x08\x2f\x56\x47\x58\x4e"
                         "\x6a\xa0\x1b\x3f\x5a\xf0\x57"
                         "\x80\x5f\x97\x3f\xf8\xec\xb8\xb2\x26\xac\x32\xad\xa6\xf0";

/* Message size in bytes */
const int msg_byte_len    = sizeof(msg) - 1;
const int digest_byte_len = sizeof(shake128) - 1;

int main(void)
{
    /* Internal function status */
    IppStatus status = ippStsNoErr;

    /* 1. Get the hash methods which is used
       Initially it is possible to pass a digest size smaller
       than it will be obtained with ippsHashSqueeze_rmf() */
    const int digest_size             = 10 * 8;
    const IppsHashMethod* hash_method = ippsHashMethod_SHAKE128(digest_size);

    /* The size of the SHAKE128 hash context structure. It will be set up in ippsHashGetSize_rmf(). */
    int context_size = 0;

    /* 2. Get the size needed for the SHAKE128 hash context structure */
    status = ippsHashGetSizeOptimal_rmf(&context_size, hash_method);
    if (!checkStatus("ippsHashGetSizeOptimal_rmf", ippStsNoErr, status)) {
        return status;
    }

    /* 3. Allocate memory for the SHAKE128 hash context structure */
    std::vector<Ipp8u> context_buffer(context_size);

    /* 4. Buffers for the digest and the tag */
    Ipp8u output_hash_buffer[digest_byte_len];
    IppsHashState_rmf* hash_state = (IppsHashState_rmf*)(context_buffer.data());

    /* 5. Initialize SHAKE128 hash context */
    status = ippsHashInit_rmf(hash_state, hash_method);
    if (!checkStatus("ippsHashInit_rmf", ippStsNoErr, status)) {
        return status;
    }

    /* 6. Call HashUpdate function to digest the message of the given length
       This function can be called multiple times for a stream of messages */
    status = ippsHashUpdate_rmf(msg, msg_byte_len, hash_state);
    if (!checkStatus("ippsHashUpdate_rmf", ippStsNoErr, status)) {
        return status;
    }

    const int digestLen = 3;

    for (int i = 0; i < digest_byte_len; i += digestLen) {
        /* 7. Squeeze the digestLen bytes of the digest value */
        status = ippsHashSqueeze_rmf(output_hash_buffer + i, digestLen, hash_state);
        if (!checkStatus("ippsHashSqueeze_rmf", ippStsNoErr, status)) {
            return status;
        }
        /* 8. Verify the resulted digest part with the known one */
        int check = memcmp(output_hash_buffer + i, shake128 + i, digestLen);
        if (check != 0) {
            printf("ERROR: Hash and the reference do not match\n");
            status = -1;
        }
    }

    /* 9. Verify the entire resulted digest with the known one */
    int check = memcmp(output_hash_buffer, shake128, digest_byte_len);
    if (check != 0) {
        printf("ERROR: Hash and the reference do not match\n");
        status = -1;
    }

    PRINT_EXAMPLE_STATUS("ippsHashUpdate_rmf", "XOF SHAKE128 Hash", !status)

    return status;
}
