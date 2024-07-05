/*************************************************************************
* Copyright (C) 2024 Intel Corporation
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
  *  \brief SM3 Hash example
  *
  *  This example demonstrates usage of Hash algorithms to digest a message by
  *  using SM3 standard.
  *  Reduce Memory Footprint (_rmf) APIs are used in this example.
  *
  */

#include <string.h>
#include <vector>

#include "ippcp.h"
#include "examples_common.h"

/*! Message text */
static const Ipp8u msg[] = "abc";

/*! Known digest to check the results */
static const
Ipp8u sm3[] = "\x66\xc7\xf0\xf4\x62\xee\xed\xd9\xd1\xf2\xd4\x6b\xdc\x10\xe4\xe2"
              "\x41\x67\xc4\x87\x5c\xf2\xf7\xa2\x29\x7d\xa0\x2b\x8f\x4b\xa8\xe0";

/*! Message size in bytes */
static const int msg_byte_len = sizeof(msg)-1;

int main(void)
{
    /*! Internal function status */
    IppStatus status = ippStsNoErr;

    /*! 1. Get the hash methods which is used */
    IppsHashMethod* hash_method = (IppsHashMethod*)ippsHashMethod_SM3();

    /*! The digest size of the SM3 standard */
    Ipp32u hash_size = IPP_SM3_DIGEST_BYTESIZE;

    /*! The size of the SM3 hash context structure. It will be set up in ippsHashGetSize_rmf(). */
    int context_size = 0;

    /*! 2. Get the size needed for the SM3 hash context structure */
    status = ippsHashGetSize_rmf(&context_size);
    if (!checkStatus("ippsHashGetSize", ippStsNoErr, status)) {
        return status;
    }

    /*! 3. Allocate memory for the SM3 hash context structure */
    std::vector<Ipp8u> context_buffer(context_size);

    /*! 4. Buffers for the digest and the tag */
    Ipp8u output_hash_buffer[IPP_SM3_DIGEST_BYTESIZE];
    Ipp8u output_tag_buffer[IPP_SM3_DIGEST_BYTESIZE];

    IppsHashState_rmf* hash_state = (IppsHashState_rmf*)(context_buffer.data());

    /*! 5. Initialize the initial SM3 hash context */
    status = ippsHashInit_rmf(hash_state, hash_method);
    if (!checkStatus("ippsHashInit", ippStsNoErr, status)) {
        return status;
    }

    /*! 6. Call HashUpdate function to digest the message of the given length */
    /*! This function can be called consequently for a stream of messages */
    status = ippsHashUpdate_rmf(msg, msg_byte_len, hash_state);
    if (!checkStatus("ippsHashUpdate", ippStsNoErr, status)) {
        return status;
    }

    /*! 7. Compute the current digest value of the processed part of the message */
    status = ippsHashGetTag_rmf(output_tag_buffer, hash_size, hash_state);
    if (!checkStatus("ippsHashGetTag", ippStsNoErr, status)) {
        return status;
    }

    /*! 8. Complete the computation of the digest value */
    status = ippsHashFinal_rmf(output_hash_buffer, hash_state);
    if (!checkStatus("ippsHashFinal", ippStsNoErr, status)) {
        return status;
    }

    /*! 9. Verify the resulted digest with the known one */
    int check = memcmp(output_hash_buffer, sm3, hash_size);
    if(check != 0) {
        printf("ERROR: Hash and the reference do not match\n");
        status = -1;
    }

    PRINT_EXAMPLE_STATUS("ippsHashUpdate_rmf", "SM3 Hash", !status)

    return status;
}
